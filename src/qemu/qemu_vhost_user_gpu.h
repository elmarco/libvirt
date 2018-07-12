/*
 * qemu_vhost_user_gpu.h: QEMU vhost-user GPU support
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
#ifndef __QEMU_VHOST_USER_GPU_H__
# define __QEMU_VHOST_USER_GPU_H__

# include "qemu_conf.h"
# include "vircommand.h"

int qemuExtVhostUserGPUStart(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             virDomainVideoDefPtr video,
                             qemuDomainLogContextPtr logCtxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

void qemuExtVhostUserGPUStop(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             virDomainVideoDefPtr video)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuExtVhostUserGPUSetupCgroup(virQEMUDriverPtr driver,
                               virDomainDefPtr def,
                               virDomainVideoDefPtr video,
                               virCgroupPtr cgroup)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

#endif /* __QEMU_VHOST_USER_GPU_H__ */
