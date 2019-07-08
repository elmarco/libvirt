/*
 * qemu_slirp.h: QEMU Slirp support
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

#pragma once

#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "vircommand.h"

typedef enum {
    QEMU_SLIRP_FEATURE_NONE = 0,
    QEMU_SLIRP_FEATURE_IPV4,
    QEMU_SLIRP_FEATURE_IPV6,
    QEMU_SLIRP_FEATURE_TFTP,
    QEMU_SLIRP_FEATURE_DBUS_ADDRESS,
    QEMU_SLIRP_FEATURE_MIGRATE,
    QEMU_SLIRP_FEATURE_RESTRICT,
    QEMU_SLIRP_FEATURE_EXIT_WITH_PARENT,

    QEMU_SLIRP_FEATURE_LAST,
} qemuSlirpFeature;

VIR_ENUM_DECL(qemuSlirpFeature);


struct _qemuSlirp {
    int fd[2];
    virBitmapPtr features;
    pid_t pid;
};


qemuSlirpPtr qemuSlirpNew(void);

qemuSlirpPtr qemuSlirpNewForHelper(const char *helper);

void qemuSlirpFree(qemuSlirpPtr slirp);

void qemuSlirpSetFeature(qemuSlirpPtr slirp,
                         qemuSlirpFeature feature);

bool qemuSlirpHasFeature(const qemuSlirpPtr slirp,
                         qemuSlirpFeature feature);

int qemuSlirpOpen(qemuSlirpPtr slirp,
                  virQEMUDriverPtr driver,
                  virDomainDefPtr def);

int qemuSlirpStart(qemuSlirpPtr slirp,
                   virDomainObjPtr vm,
                   virQEMUDriverPtr driver,
                   virDomainNetDefPtr net,
                   qemuProcessIncomingDefPtr incoming);

void qemuSlirpStop(qemuSlirpPtr slirp,
                   virDomainObjPtr vm,
                   virQEMUDriverPtr driver,
                   virDomainNetDefPtr net);

int qemuSlirpGetFD(qemuSlirpPtr slirp);

VIR_DEFINE_AUTOPTR_FUNC(qemuSlirp, qemuSlirpFree);
