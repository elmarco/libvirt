/*
 * qemu_dbus.c: QEMU dbus daemon
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

#include "qemu_extdevice.h"
#include "qemu_dbus.h"
#include "qemu_security.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.dbus");


int
qemuDBusPrepareHost(virQEMUDriverPtr driver)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    return virDirCreate(cfg->dbusStateDir, 0770, cfg->user, cfg->group,
                        VIR_DIR_CREATE_ALLOW_EXIST);
}


static char *
qemuDBusCreatePidFilename(const char *stateDir,
                          const char *shortName)
{
    VIR_AUTOFREE(char *) name = NULL;

    if (virAsprintf(&name, "%s-dbus", shortName) < 0)
        return NULL;

    return virPidFileBuildPath(stateDir, name);
}


static char *
qemuDBusCreateFilename(const char *stateDir,
                       const char *shortName,
                       const char *ext)
{
    VIR_AUTOFREE(char *) name = NULL;

    if (virAsprintf(&name, "%s-dbus", shortName) < 0)
        return NULL;

    return virFileBuildPath(stateDir, name,  ext);
}


static char *
qemuDBusCreateSocketPath(virQEMUDriverConfigPtr cfg,
                         const char *shortName)
{
    return qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".sock");
}


char *
qemuDBusGetAddress(virQEMUDriverPtr driver,
                   virDomainObjPtr vm)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOFREE(char *) shortName = virDomainDefGetShortName(vm->def);
    VIR_AUTOFREE(char *) path = qemuDBusCreateSocketPath(cfg, shortName);
    char *ret;

    ignore_value(virAsprintf(&ret, "unix:path=%s", path));

    return ret;
}


static int
qemuDBusGetPid(const char *binPath,
               const char *stateDir,
               const char *shortName,
               pid_t *pid)
{
    VIR_AUTOFREE(char *) pidfile = qemuDBusCreatePidFilename(stateDir, shortName);

    if (!pidfile)
        return -ENOMEM;

    return virPidFileReadPathIfAlive(pidfile, pid, binPath);
}


static int
qemuDBusWriteConfig(const char *filename, const char *path)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOFREE(char *) config = NULL;

    virBufferAddLit(&buf, "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n");
    virBufferAddLit(&buf, "  \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n");
    virBufferAddLit(&buf, "<busconfig>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferAddLit(&buf, "<type>org.libvirt.qemu</type>\n");

    /* This may become useful: */
    /* virBufferAddLit(&buf, "<servicedir>" DATADIR "/dbus-1/libvirt-qemu-services</servicedir>\n"); */

    virBufferAsprintf(&buf, "<listen>unix:path=%s</listen>\n", path);

    virBufferAddLit(&buf, "<auth>EXTERNAL</auth>\n");

    virBufferAddLit(&buf, "<policy context='default'>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAddLit(&buf, "<!-- Allow everything to be sent -->\n");
    virBufferAddLit(&buf, "<allow send_destination='*' eavesdrop='true'/>\n");
    virBufferAddLit(&buf, "<!-- Allow everything to be received -->\n");
    virBufferAddLit(&buf, "<allow eavesdrop='true'/>\n");
    virBufferAddLit(&buf, "<!-- Allow anyone to own anything -->\n");
    virBufferAddLit(&buf, "<allow own='*'/>\n");
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</policy>\n");

    virBufferAddLit(&buf, "<include if_selinux_enabled='yes' selinux_root_relative='yes'>contexts/dbus_contexts</include>\n");

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</busconfig>\n");

    if (virBufferCheckError(&buf) < 0)
        return -1;

    config = virBufferContentAndReset(&buf);

    return virFileWriteStr(filename, config, 0600);
}


void
qemuDBusStop(virQEMUDriverPtr driver,
             virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOFREE(char *) shortName = NULL;
    VIR_AUTOFREE(char *) pidfile = NULL;
    VIR_AUTOFREE(char *) configfile = NULL;
    virErrorPtr orig_err;
    int rc;
    pid_t pid;

    shortName = virDomainDefGetShortName(vm->def);
    pidfile = qemuDBusCreatePidFilename(cfg->dbusStateDir, shortName);
    configfile = qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".conf");

    if (!shortName || !pidfile || !configfile)
        return;

    rc = qemuDBusGetPid(cfg->dbusDaemonName, cfg->dbusStateDir, shortName, &pid);
    if (rc == 0 && pid != (pid_t)-1) {
        char ebuf[1024];

        VIR_DEBUG("Killing dbus-daemon process %lld", (long long)pid);
        if (virProcessKill(pid, SIGTERM) < 0 && errno != ESRCH)
            VIR_ERROR(_("Failed to kill process %lld: %s"),
                      (long long)pid,
                      virStrerror(errno, ebuf, sizeof(ebuf)));
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill dbus-daemon process");
    } else {
        if (unlink(pidfile) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove stale pidfile %s"),
                                 pidfile);
        }
    }
    if (unlink(configfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove stale configfile %s"),
                             pidfile);
    }
    virErrorRestore(&orig_err);

    VIR_FREE(pidfile);

    priv->dbusDaemonRunning = false;
}


int
qemuDBusStart(virQEMUDriverPtr driver,
              virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) shortName = NULL;
    VIR_AUTOFREE(char *) pidfile = NULL;
    VIR_AUTOFREE(char *) configfile = NULL;
    VIR_AUTOFREE(char *) sockpath = NULL;
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500 * 1000; /* ms */
    int errfd = -1;
    int cmdret = 0;
    int exitstatus = 0;

    if (priv->dbusDaemonRunning)
        return 0;

    /* cleanup */
    qemuDBusStop(driver, vm);

    cmd = virCommandNew(cfg->dbusDaemonName);
    shortName = virDomainDefGetShortName(vm->def);
    pidfile = qemuDBusCreatePidFilename(cfg->dbusStateDir, shortName);
    configfile = qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".conf");
    sockpath = qemuDBusCreateSocketPath(cfg, shortName);

    if (!cmd || !pidfile || !configfile || !sockpath)
        return -1;

    if (qemuDBusWriteConfig(configfile, sockpath) < 0) {
        virReportSystemError(errno, _("Failed to write '%s'"), configfile);
        return -1;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, configfile, true) < 0)
        return -1;

    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetErrorFD(cmd, &errfd);
    virCommandDaemonize(cmd);
    virCommandAddArgFormat(cmd, "--config-file=%s", configfile);

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "DBus") < 0)
        return -1;

    if (qemuSecurityCommandRun(driver, vm, cmd,
                               &exitstatus, &cmdret) < 0)
        return -1;

    if (cmdret < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'vhost-user-gpu'. exitstatus: %d"),
                       exitstatus);
        return -1;
    }

    if (virTimeBackOffStart(&timebackoff, 1, timeout) < 0)
        return -1;
    while (virTimeBackOffWait(&timebackoff)) {
        pid_t pid;

        if (qemuDBusGetPid(cfg->dbusDaemonName, cfg->dbusStateDir, shortName, &pid) < 0)
            continue;

        if (pid == (pid_t)-1)
            break;

        if (virFileExists(sockpath))
            break;
    }

    if (!virFileExists(sockpath)) {
        char errbuf[1024] = { 0 };

        if (saferead(errfd, errbuf, sizeof(errbuf) - 1) < 0) {
            virReportSystemError(errno, "%s", _("dbus-daemon died unexpectedly"));
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("dbus-daemon died and reported: %s"), errbuf);
        }

        return -1;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, sockpath, true) < 0)
        return -1;

    priv->dbusDaemonRunning = true;

    return 0;
}


int
qemuDBusSetupCgroup(virQEMUDriverPtr driver,
                    virDomainDefPtr def,
                    virCgroupPtr cgroup)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOFREE(char *) shortName = virDomainDefGetShortName(def);
    pid_t pid;
    int rc;

    rc = qemuDBusGetPid(cfg->dbusDaemonName, cfg->dbusStateDir, shortName, &pid);
    if (rc < 0 || (rc == 0 && pid == (pid_t)-1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get process id of dbus-daemon"));
        return -1;
    }

    if (virCgroupAddProcess(cgroup, pid) < 0)
        return -1;

    return 0;
}


int
qemuDBusConnect(virQEMUDriverPtr driver,
                virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    VIR_AUTOFREE(char *) addr = qemuDBusGetAddress(driver, vm);
    DBusConnection *conn = NULL;
    DBusError error;
    int ret = -1;

    if (!priv->dbusDaemonRunning || priv->dbusConn)
        return 0;

    dbus_error_init(&error);
    conn = dbus_connection_open(addr, &error);
    if (!conn) {
        virReportError(VIR_ERR_DBUS_SERVICE, _("failed to connect to DBus: %s"),
                       error.message ? : _("unknown error"));
        goto end;
    }

    if (!dbus_bus_register(conn, &error)) {
        virReportError(VIR_ERR_DBUS_SERVICE, _("failed to register to DBus: %s"),
                       error.message ? : _("unknown error"));
        goto end;
    }

    priv->dbusConn = conn;
    conn = NULL;
    ret = 0;

end:
    if (conn) {
        dbus_connection_unref(conn);
    }
    dbus_error_free(&error);
    return ret;
}
