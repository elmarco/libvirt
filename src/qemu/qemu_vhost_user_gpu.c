/*
 * qemu_vhost_user_gpu.c: QEMU vhost-user GPU support
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Marc-André Lureau <marcandre.lureau@redhat.com>
 */

#include <config.h>

#include "qemu_extdevice.h"
#include "qemu_domain.h"
#include "qemu_security.h"

#include "conf/domain_conf.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virlog.h"
#include "virutil.h"
#include "virfile.h"
#include "virstring.h"
#include "virtime.h"
#include "virpidfile.h"
#include "qemu_vhost_user_gpu.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.vhost-user-gpu")

/*
 * Look up the vhost-user-gpu executable; to be found on the host
 */
static char *vhost_user_gpu_path;

static int
qemuVhostUserGPUInit(void)
{
    if (!vhost_user_gpu_path) {
        vhost_user_gpu_path = virFindFileInPath("vhost-user-gpu");
        if (!vhost_user_gpu_path) {
            virReportSystemError(ENOENT, "%s",
                                 _("Unable to find 'vhost-user-gpu' binary in $PATH"));
            return -1;
        }
        if (!virFileIsExecutable(vhost_user_gpu_path)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("vhost-user-gpu %s is not an executable"),
                           vhost_user_gpu_path);
            VIR_FREE(vhost_user_gpu_path);
            return -1;
        }
    }

    return 0;
}


static char *
qemuVhostUserGPUCreatePidFilename(const char *stateDir,
                                  const char *shortName,
                                  const char *alias)
{
    char *pidfile = NULL;
    char *devicename = NULL;

    if (virAsprintf(&devicename, "%s-%s-vhost-user-gpu", shortName, alias) < 0)
        return NULL;

    pidfile = virPidFileBuildPath(stateDir, devicename);

    VIR_FREE(devicename);

    return pidfile;
}


/*
 * qemuVhostUserGPUGetPid
 *
 * @stateDir: the directory where vhost-user-gpu writes the pidfile into
 * @shortName: short name of the domain
 * @alias: video device alias
 * @pid: pointer to pid
 *
 * Return -errno upon error, or zero on successful reading of the pidfile.
 * If the PID was not still alive, zero will be returned, and @pid will be
 * set to -1;
 */
static int
qemuVhostUserGPUGetPid(const char *stateDir,
                       const char *shortName,
                       const char *alias,
                       pid_t *pid)
{
    int ret;
    char *pidfile = qemuVhostUserGPUCreatePidFilename(stateDir, shortName, alias);
    if (!pidfile)
        return -ENOMEM;

    ret = virPidFileReadPathIfAlive(pidfile, pid, vhost_user_gpu_path);

    VIR_FREE(pidfile);

    return ret;
}


/*
 * qemuExtVhostUserGPUStart:
 *
 * @driver: QEMU driver
 * @def: domain definition
 * @video: the video device
 * @logCtxt: log context
 *
 * Start the external vhost-user-gpu process:
 * - open a socketpair for vhost-user communication
 * - have the command line built
 * - start the external process and sync with it before QEMU start
 */
int qemuExtVhostUserGPUStart(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             virDomainVideoDefPtr video,
                             qemuDomainLogContextPtr logCtxt)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    int exitstatus = 0;
    char *errbuf = NULL;
    virQEMUDriverConfigPtr cfg;
    char *pidfile, *shortName = virDomainDefGetShortName(def);
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500000; /* ms */
    int cmdret = 0, rc;
    int pair[2] = { -1, -1 };

    pid_t pid;

    if (!shortName)
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    /* stop any left-over for this VM */
    qemuExtVhostUserGPUStop(driver, def, video);

    if (!(pidfile = qemuVhostUserGPUCreatePidFilename(
              cfg->stateDir, shortName, video->info.alias)))
        goto error;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        virReportSystemError(errno, "%s", _("failed to create socket"));
        goto error;
    }

    cmd = virCommandNew(vhost_user_gpu_path);
    if (!cmd)
        goto error;

    virCommandClearCaps(cmd);
    virCommandDaemonize(cmd);

    if (qemuExtDeviceLogCommand(logCtxt, cmd, "vhost-user-gpu") < 0)
        goto error;

    virCommandAddArgList(cmd, "--pid", pidfile, NULL);
    virCommandAddArgFormat(cmd, "--fd=%d", pair[0]);
    virCommandPassFD(cmd, pair[0], VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    pair[0] = -1;

    if (video->accel && video->accel->accel3d) {
        virCommandAddArg(cmd, "--virgl");
    }
    if (qemuSecurityStartVhostUserGPU(driver, def, cmd,
                                      &exitstatus, &cmdret) < 0)
        goto error;

    if (cmdret < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'vhost-user-gpu'. exitstatus: %d, "
                         "error: %s"), exitstatus, errbuf);
        goto cleanup;
    }

    /* check that the helper has written its pid into the file */
    if (virTimeBackOffStart(&timebackoff, 1, timeout) < 0)
        goto error;
    while (virTimeBackOffWait(&timebackoff)) {
        rc = qemuVhostUserGPUGetPid(cfg->stateDir, shortName, video->info.alias, &pid);
        if (rc < 0)
            continue;
        if (rc == 0 && pid == (pid_t)-1)
            goto error;
        break;
    }

    ret = 0;
    video->info.vhost_user_fd = pair[1];
    pair[1] = -1;

cleanup:
    VIR_FORCE_CLOSE(pair[0]);
    VIR_FORCE_CLOSE(pair[1]);
    virObjectUnref(cfg);
    VIR_FREE(pidfile);
    virCommandFree(cmd);

    return ret;

error:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("vhost-user-gpu failed to start"));
    goto cleanup;
}


/*
 * qemuExtVhostUserGPUStop:
 *
 * @driver: QEMU driver
 * @def: domain definition
 * @video: the video device
 *
 * Check if vhost-user process pidfile is around, kill the process,
 * and remove the pidfile.
 */
void qemuExtVhostUserGPUStop(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             virDomainVideoDefPtr video)
{
    virErrorPtr orig_err;
    char *pidfile, *shortName = virDomainDefGetShortName(def);
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (qemuVhostUserGPUInit() < 0)
        return;

    if (!(pidfile = qemuVhostUserGPUCreatePidFilename(
              cfg->stateDir, shortName, video->info.alias))) {
        VIR_WARN("Unable to construct vhost-user-gpu pidfile path");
        return;
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill vhost-user-gpu process");
    } else {
        if (unlink(pidfile) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove stale pidfile %s"),
                                 pidfile);
        }
    }
    virErrorRestore(&orig_err);

    VIR_FREE(pidfile);
}


/*
 * qemuExtVhostUserGPUSetupCgroup:
 *
 * @driver: QEMU driver
 * @def: domain definition
 * @video: the video device
 * @cgroupe: a cgroup
 *
 * Add the vhost-user-gpu PID to the given cgroup.
 */
int
qemuExtVhostUserGPUSetupCgroup(virQEMUDriverPtr driver,
                               virDomainDefPtr def,
                               virDomainVideoDefPtr video,
                               virCgroupPtr cgroup)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    char *pidfile = NULL;
    char *shortName = NULL;
    int ret = -1, rc;
    pid_t pid;

    shortName = virDomainDefGetShortName(def);
    if (!shortName)
        goto cleanup;

    rc = qemuVhostUserGPUGetPid(cfg->stateDir, shortName, video->info.alias, &pid);
    if (rc < 0 || (rc == 0 && pid == (pid_t)-1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get process id of vhost-user-gpu"));
        goto cleanup;
    }
    if (virCgroupAddTask(cgroup, pid) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(pidfile);
    VIR_FREE(shortName);
    virObjectUnref(cfg);

    return ret;
}
