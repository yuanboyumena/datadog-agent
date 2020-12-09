//go:generate go run github.com/mailru/easyjson/easyjson -build_tags linux $GOFILE

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux

package probe

import (
	"syscall"
	"time"
)

// FIMCategory holds the event category for JSON serialization
const FIMCategory = "File Activity"

// FileSerializer serializes a file to JSON
// easyjson:json
type FileSerializer struct {
	Path            string    `json:"path,omitempty"`
	Name            string    `json:"name,omitempty"`
	ContainerPath   string    `json:"container_path,omitempty"`
	Inode           uint64    `json:"inode,omitempty"`
	Mode            uint32    `json:"mode,omitempty"`
	OverlayNumLower int32     `json:"overlay_numlower,omitempty"`
	MountID         uint32    `json:"mount_id"`
	UID             int32     `json:"uid"`
	GID             int32     `json:"gid"`
	XAttrName       string    `json:"attribute_name,omitempty"`
	XAttrNamespace  string    `json:"attribute_namespace,omitempty"`
	Flags           string    `json:"flags,omitempty"`
	Atime           time.Time `json:"access_time,omitempty"`
	Mtime           time.Time `json:"modification_time,omitempty"`
}

// ProcessCacheEntrySerializer serializes a process cache entry to JSON
// easyjson:json
type ProcessCacheEntrySerializer struct {
	Pid           uint32    `json:"pid"`
	Tid           uint32    `json:"tid"`
	UID           uint32    `json:"uid"`
	GID           uint32    `json:"gid"`
	User          string    `json:"user,omitempty"`
	Group         string    `json:"group,omitempty"`
	Name          string    `json:"name"`
	ContainerPath string    `json:"executable_container_path,omitempty"`
	Path          string    `json:"executable_path"`
	Inode         uint64    `json:"executable_inode"`
	MountID       uint32    `json:"executable_mount_id"`
	TTY           string    `json:"tty,omitempty"`
	ForkTime      time.Time `json:"fork_time,omitempty"`
	ExecTime      time.Time `json:"exec_time,omitempty"`
	ExitTime      time.Time `json:"exit_time,omitempty"`
}

// ContainerContextSerializer serializes a container context to JSON
// easyjson:json
type ContainerContextSerializer struct {
	ID string `json:"id,omitempty"`
}

// FileEventSerializer serializes a file event to JSON
// easyjson:json
type FileEventSerializer struct {
	*FileSerializer
	Destination *FileSerializer `json:"destination,omitempty"`

	// Specific to mount events
	MountID uint32 `json:"mount_id,omitempty"`
	GroupID uint32 `json:"group_id,omitempty"`
	Device  uint32 `json:"device,omitempty"`
	FSType  string `json:"fstype,omitempty"`
}

// EventContextSerializer serializes an event context to JSON
// easyjson:json
type EventContextSerializer struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Outcome  string `json:"outcome"`
}

// ProcessContextSerializer serializes a process context to JSON
// easyjson:json
type ProcessContextSerializer struct {
	*ProcessCacheEntrySerializer
	Parent    *ProcessCacheEntrySerializer   `json:"parent"`
	Ancestors []*ProcessCacheEntrySerializer `json:"ancestors"`
}

// EventSerializer serializes an event to JSON
// easyjson:json
type EventSerializer struct {
	*EventContextSerializer    `json:"evt"`
	*FileEventSerializer       `json:"file"`
	ProcessContextSerializer   *ProcessContextSerializer   `json:"process"`
	ContainerContextSerializer *ContainerContextSerializer `json:"container,omitempty"`
}

func newFileSerializer(fe *FileEvent, e *Event) *FileSerializer {
	return &FileSerializer{
		Path:            fe.ResolveInode(e),
		ContainerPath:   fe.ResolveContainerPath(e),
		Inode:           fe.Inode,
		MountID:         fe.MountID,
		OverlayNumLower: fe.OverlayNumLower,
	}
}

func newProcessCacheEntrySerializer(pce *ProcessCacheEntry, e *Event) *ProcessCacheEntrySerializer {
	return &ProcessCacheEntrySerializer{
		Pid:      pce.Pid,
		Tid:      pce.Tid,
		UID:      pce.UID,
		GID:      pce.GID,
		User:     pce.ResolveUser(e),
		Group:    pce.ResolveGroup(e),
		Name:     pce.Comm,
		Path:     pce.ResolveInode(e),
		Inode:    pce.Inode,
		MountID:  pce.MountID,
		TTY:      pce.ResolveTTY(e),
		ForkTime: pce.ForkTimestamp,
		ExecTime: pce.ExecTimestamp,
		ExitTime: pce.ExitTimestamp,
	}
}

func newContainerContextSerializer(cc *ContainerContext, e *Event) *ContainerContextSerializer {
	return &ContainerContextSerializer{
		ID: cc.ResolveContainerID(e),
	}
}

func newProcessContextSerializer(pc *ProcessContext, e *Event) *ProcessContextSerializer {
	entry := e.ResolveProcessCacheEntry()

	ps := &ProcessContextSerializer{
		ProcessCacheEntrySerializer: newProcessCacheEntrySerializer(entry, e),
	}

	ancestor := entry.Parent
	for i := 0; ancestor != nil && len(ancestor.PathnameStr) > 0; i++ {
		s := newProcessCacheEntrySerializer(ancestor, e)
		ps.Ancestors = append(ps.Ancestors, s)
		if i == 0 {
			ps.Parent = s
		}
		ancestor = ancestor.Parent
	}

	return ps
}

func serializeSyscallRetval(retval int64) string {
	switch {
	case syscall.Errno(retval) == syscall.EACCES || syscall.Errno(retval) == syscall.EPERM:
		return "Refused"
	case retval < 0:
		return "Error"
	default:
		return "Success"
	}
}

func newEventSerializer(event *Event) (*EventSerializer, error) {
	s := &EventSerializer{
		EventContextSerializer: &EventContextSerializer{
			Name:     EventType(event.Type).String(),
			Category: FIMCategory,
		},
	}

	switch EventType(event.Type) {
	case FileChmodEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Chmod.FileEvent, event),
		}
		s.FileSerializer.Mode = event.Chmod.Mode
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Chmod.Retval)
	case FileChownEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Chown.FileEvent, event),
		}
		s.FileSerializer.UID = event.Chown.UID
		s.FileSerializer.GID = event.Chown.GID
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Chown.Retval)
	case FileLinkEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Chown.FileEvent, event),
			Destination:    newFileSerializer(&event.Link.Target, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Link.Retval)
	case FileOpenEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Open.FileEvent, event),
		}
		s.FileSerializer.Mode = event.Open.Mode
		s.FileSerializer.Flags = OpenFlags(event.Open.Flags).String()
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Open.Retval)
	case FileMkdirEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Mkdir.FileEvent, event),
		}
		s.FileSerializer.Mode = event.Mkdir.Mode
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Mkdir.Retval)
	case FileRmdirEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Rmdir.FileEvent, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Rmdir.Retval)
	case FileUnlinkEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Unlink.FileEvent, event),
		}
		s.FileSerializer.Flags = UnlinkFlags(event.Unlink.Flags).String()
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Unlink.Retval)
	case FileRenameEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Rename.Old, event),
			Destination:    newFileSerializer(&event.Rename.New, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Rename.Retval)
	case FileRemoveXAttrEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.RemoveXAttr.FileEvent, event),
		}
		s.FileSerializer.XAttrName = event.RemoveXAttr.Name
		s.FileSerializer.XAttrName = event.RemoveXAttr.Namespace
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.RemoveXAttr.Retval)
	case FileSetXAttrEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.SetXAttr.FileEvent, event),
		}
		s.FileSerializer.XAttrName = event.SetXAttr.Name
		s.FileSerializer.XAttrName = event.SetXAttr.Namespace
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.SetXAttr.Retval)
	case FileUtimeEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Utimes.FileEvent, event),
		}
		s.FileSerializer.Atime = event.Utimes.Atime
		s.FileSerializer.Mtime = event.Utimes.Mtime
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Utimes.Retval)
	case FileMountEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: &FileSerializer{
				Path:    event.Mount.ResolveRoot(event),
				MountID: event.Mount.RootMountID,
				Inode:   event.Mount.RootInode,
			},
			Destination: &FileSerializer{
				Path:    event.Mount.ResolveMountPoint(event),
				MountID: event.Mount.ParentMountID,
				Inode:   event.Mount.ParentInode,
			},
			MountID: event.Mount.MountID,
			GroupID: event.Mount.GroupID,
			Device:  event.Mount.Device,
			FSType:  event.Mount.GetFSType(),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Mount.Retval)
	case FileUmountEventType:
		s.FileEventSerializer = &FileEventSerializer{
			MountID: event.Umount.MountID,
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(event.Umount.Retval)
	case ForkEventType:
		s.EventContextSerializer.Outcome = serializeSyscallRetval(0)
	case ExitEventType:
		s.EventContextSerializer.Outcome = serializeSyscallRetval(0)
	case ExecEventType:
		s.FileEventSerializer = &FileEventSerializer{
			FileSerializer: newFileSerializer(&event.Exec.FileEvent, event),
		}
		s.EventContextSerializer.Outcome = serializeSyscallRetval(0)
	}

	s.ProcessContextSerializer = newProcessContextSerializer(&event.Process, event)
	if event.Container.ID != "" {
		s.ContainerContextSerializer = newContainerContextSerializer(&event.Container, event)
	}

	return s, nil
}
