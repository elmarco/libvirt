/*
 * qemu_slirp.c: QEMU Slirp support
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
 */

#include <config.h>

#include "qemu_dbus.h"
#include "qemu_extdevice.h"
#include "qemu_security.h"
#include "qemu_slirp.h"
#include "viralloc.h"
#include "virenum.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virstring.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.slirp");

VIR_ENUM_IMPL(qemuSlirpFeature,
              QEMU_SLIRP_FEATURE_LAST,
              "",
              "ipv4",
              "ipv6",
              "tftp",
              "dbus-address",
              "migrate",
              "restrict",
              "exit-with-parent",
);


void
qemuSlirpFree(qemuSlirpPtr slirp)
{
    VIR_FORCE_CLOSE(slirp->fd[0]);
    VIR_FORCE_CLOSE(slirp->fd[1]);
    virBitmapFree(slirp->features);
    VIR_FREE(slirp);
}


void
qemuSlirpSetFeature(qemuSlirpPtr slirp,
                    qemuSlirpFeature feature)
{
    ignore_value(virBitmapSetBit(slirp->features, feature));
}


bool
qemuSlirpHasFeature(const qemuSlirpPtr slirp,
                    qemuSlirpFeature feature)
{
    return virBitmapIsBitSet(slirp->features, feature);
}


qemuSlirpPtr
qemuSlirpNew(void)
{
    qemuSlirpPtr slirp = NULL;

    if (VIR_ALLOC(slirp) < 0)
        return NULL;

    slirp->pid = (pid_t)-1;
    slirp->fd[0] = slirp->fd[1] = -1;
    slirp->features = virBitmapNew(QEMU_SLIRP_FEATURE_LAST);

    return slirp;
}


qemuSlirpPtr
qemuSlirpNewForHelper(const char *helper)
{
    VIR_AUTOPTR(qemuSlirp) slirp = NULL;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) output = NULL;
    VIR_AUTOPTR(virJSONValue) doc = NULL;
    virJSONValuePtr featuresJSON;
    size_t i, nfeatures;

    if (!helper)
        return NULL;

    slirp = qemuSlirpNew();
    if (!slirp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to allocate slirp for '%s'"), helper);
        return NULL;
    }

    cmd = virCommandNewArgList(helper, "--print-capabilities", NULL);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0)
        return NULL;

    if (!(doc = virJSONValueFromString(output)) ||
        !(featuresJSON = virJSONValueObjectGetArray(doc, "features"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse json capabilities '%s'"),
                       helper);
        return NULL;
    }

    nfeatures = virJSONValueArraySize(featuresJSON);
    for (i = 0; i < nfeatures; i++) {
        virJSONValuePtr item = virJSONValueArrayGet(featuresJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuSlirpFeatureTypeFromString(tmpStr)) <= 0) {
            VIR_WARN("unknown slirp feature %s", tmpStr);
            continue;
        }

        qemuSlirpSetFeature(slirp, tmp);
    }

    VIR_RETURN_PTR(slirp);
}


static char *
qemuSlirpCreatePidFilename(const char *stateDir,
                           const char *shortName,
                           const char *alias)
{
    VIR_AUTOFREE(char *) name = NULL;

    if (virAsprintf(&name, "%s-%s-slirp", shortName, alias) < 0)
        return NULL;

    return virPidFileBuildPath(stateDir, name);
}


static int
qemuSlirpGetPid(const char *binPath,
                const char *stateDir,
                const char *shortName,
                const char *alias,
                pid_t *pid)
{
    VIR_AUTOFREE(char *) pidfile = qemuSlirpCreatePidFilename(stateDir, shortName, alias);
    if (!pidfile)
        return -ENOMEM;

    return virPidFileReadPathIfAlive(pidfile, pid, binPath);
}


int
qemuSlirpOpen(qemuSlirpPtr slirp,
              virQEMUDriverPtr driver,
              virDomainDefPtr def)
{
    int rc, pair[2] = { -1, -1 };

    if (qemuSecuritySetSocketLabel(driver->securityManager, def) < 0)
        goto error;

    rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);

    if (qemuSecurityClearSocketLabel(driver->securityManager, def) < 0)
        goto error;

    if (rc < 0) {
        virReportSystemError(errno, "%s", _("failed to create socketpair"));
        goto error;
    }

    slirp->fd[0] = pair[0];
    slirp->fd[1] = pair[1];

    return 0;

error:
    VIR_FORCE_CLOSE(pair[0]);
    VIR_FORCE_CLOSE(pair[1]);
    return -1;
}


int
qemuSlirpGetFD(qemuSlirpPtr slirp)
{
    int fd = slirp->fd[0];
    slirp->fd[0] = -1;
    return fd;
}


static char *
qemuSlirpGetDBusVMStateId(virDomainNetDefPtr net)
{
    char macstr[VIR_MAC_STRING_BUFLEN] = "";
    char *id = NULL;

    /* can't use alias, because it's not stable across restarts */
    if (virAsprintf(&id, "slirp-%s", virMacAddrFormat(&net->mac, macstr)) < 0)
        return NULL;

    return id;
}


void
qemuSlirpStop(qemuSlirpPtr slirp,
              virDomainObjPtr vm,
              virQEMUDriverPtr driver,
              virDomainNetDefPtr net)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOFREE(char *) pidfile = NULL;
    VIR_AUTOFREE(char *) shortName = virDomainDefGetShortName(vm->def);
    VIR_AUTOFREE(char *) id = qemuSlirpGetDBusVMStateId(net);
    virErrorPtr orig_err;
    int rc;
    pid_t pid;

    if (!(pidfile = qemuSlirpCreatePidFilename(
              cfg->stateDir, shortName, net->info.alias))) {
        VIR_WARN("Unable to construct slirp pidfile path");
        return;
    }

    qemuDBusVMStateRemove(vm, id);

    rc = qemuSlirpGetPid(cfg->slirpHelperName,
                         cfg->stateDir, shortName, net->info.alias, &pid);
    if (rc == 0 && pid != (pid_t)-1) {
        char ebuf[1024];

        VIR_DEBUG("Killing slirp process %lld", (long long)pid);
        if (virProcessKill(pid, SIGKILL) < 0 && errno != ESRCH)
            VIR_ERROR(_("Failed to kill process %lld: %s"),
                      (long long)pid,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill slirp process");
    } else {
        if (unlink(pidfile) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove stale pidfile %s"),
                                 pidfile);
        }
    }
    virErrorRestore(&orig_err);
    slirp->pid = 0;
}


int
qemuSlirpStart(qemuSlirpPtr slirp,
               virDomainObjPtr vm,
               virQEMUDriverPtr driver,
               virDomainNetDefPtr net,
               qemuProcessIncomingDefPtr incoming)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) cmdstr = NULL;
    VIR_AUTOFREE(char *) addr = NULL;
    VIR_AUTOFREE(char *) pidfile = NULL;
    VIR_AUTOFREE(char *) shortName = virDomainDefGetShortName(vm->def);
    size_t i;
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500 * 1000; /* ms */
    pid_t pid;
    int cmdret = 0, exitstatus = 0;

    if (incoming &&
        !qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The slirp-helper doesn't support migration"));
    }

    if (!(pidfile = qemuSlirpCreatePidFilename(
              cfg->stateDir, shortName, net->info.alias)))
        return -1;

    if (!(cmd = virCommandNew(cfg->slirpHelperName)))
        return -1;

    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    virCommandAddArgFormat(cmd, "--fd=%d", slirp->fd[1]);
    virCommandPassFD(cmd, slirp->fd[1],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    slirp->fd[1] = -1;

    for (i = 0; i < net->guestIP.nips; i++) {
        const virNetDevIPAddr *ip = net->guestIP.ips[i];
        const char *opt = "";

        if (!(addr = virSocketAddrFormat(&ip->address)))
            return -1;

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET))
            opt = "--net";
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6))
            opt = "--prefix-ipv6";

        virCommandAddArgFormat(cmd, "%s=%s", opt, addr);
        VIR_FREE(addr);

        if (ip->prefix) {
            if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET)) {
                virSocketAddr netmask;
                VIR_AUTOFREE(char *) netmaskStr = NULL;

                if (virSocketAddrPrefixToNetmask(ip->prefix, &netmask, AF_INET) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Failed to translate prefix %d to netmask"),
                                   ip->prefix);
                    return -1;
                }
                if (!(netmaskStr = virSocketAddrFormat(&netmask)))
                    return -1;
                virCommandAddArgFormat(cmd, "--mask=%s", netmaskStr);
            }
            if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6))
                virCommandAddArgFormat(cmd, "--prefix-length-ipv6=%u", ip->prefix);
        }
    }

    if (qemuSlirpHasFeature(slirp,
                            QEMU_SLIRP_FEATURE_DBUS_ADDRESS)) {
        VIR_AUTOFREE(char *) id = qemuSlirpGetDBusVMStateId(net);
        VIR_AUTOFREE(char *) dbus_addr = qemuDBusGetAddress(driver, vm);

        if (qemuDBusStart(driver, vm) < 0)
            return -1;

        virCommandAddArgFormat(cmd, "--dbus-id=%s", id);

        virCommandAddArgFormat(cmd, "--dbus-address=%s", dbus_addr);

        if (qemuSlirpHasFeature(slirp,
                                QEMU_SLIRP_FEATURE_MIGRATE)) {
            if (qemuDBusVMStateAdd(vm, id) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to register slirp migration"));
                return -1;
            }
            if (incoming) {
                virCommandAddArg(cmd, "--dbus-incoming");
            }
        }
    }

    if (qemuSlirpHasFeature(slirp,
                            QEMU_SLIRP_FEATURE_EXIT_WITH_PARENT)) {
        virCommandAddArg(cmd, "--exit-with-parent");
    }

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "slirp") < 0)
        return -1;

    if (qemuSecurityCommandRun(driver, vm, cmd,
                               &exitstatus, &cmdret) < 0)
        return -1;

    if (cmdret < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'slirp'. exitstatus: %d"), exitstatus);
        return -1;
    }

    /* check that the helper has written its pid into the file */
    if (virTimeBackOffStart(&timebackoff, 1, timeout) < 0)
        return -1;
    while (virTimeBackOffWait(&timebackoff)) {
        int rc = qemuSlirpGetPid(cfg->slirpHelperName,
                                 cfg->stateDir, shortName, net->info.alias, &pid);
        if (rc < 0)
            continue;
        if (rc == 0 && pid == (pid_t)-1)
            return -1;
        break;
    }

    slirp->pid = pid;
    return 0;
}
