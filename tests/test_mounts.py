from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from cozy_network_manager.app.collectors.mounts import collect_mount_topology
from cozy_network_manager.app.services.mounts import correlate_sshfs_mounts


def _write_host_files(root: Path, mountinfo: str, ssh_match: str = "") -> None:
    proc = root / "proc/1"
    proc.mkdir(parents=True)
    (proc / "mountinfo").write_text(mountinfo.strip() + "\n", encoding="utf-8")
    etc = root / "etc"
    (etc / "ssh/sshd_config.d").mkdir(parents=True)
    (etc / "ssh/sshd_config").write_text(
        "Include /etc/ssh/sshd_config.d/*.conf\nSubsystem sftp internal-sftp\n",
        encoding="utf-8",
    )
    if ssh_match:
        (etc / "ssh/sshd_config.d/exports.conf").write_text(ssh_match, encoding="utf-8")
    (etc / "passwd").write_text(
        "ruvps:x:1001:1001::/home/ruvps:/usr/sbin/nologin\n"
        "alice:x:1002:1002::/srv/sftp/alice:/usr/sbin/nologin\n",
        encoding="utf-8",
    )


def test_collects_live_sshfs_sftp_and_windows_mapping(tmp_path: Path):
    _write_host_files(
        tmp_path,
        r"""
635 27 0:167 / /mnt/ruvps-files rw,nosuid,nodev,relatime shared:233 - fuse.sshfs ruvps@10.46.0.6:/files rw,user_id=0,group_id=0,default_permissions,allow_other
156 80 0:70 /Downloads/ru-vps/files /srv/sftp/ruvps/files rw,noatime - 9p D:\134 rw,aname=drvfs;path=D:\;uid=1000;gid=1000
157 80 0:71 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000
""",
        """
Match User ruvps
    ChrootDirectory /srv/sftp/ruvps
    ForceCommand internal-sftp -d /files
""",
    )

    sshfs, exports, windows, warnings = collect_mount_topology(str(tmp_path))

    assert [item.model_dump() for item in sshfs] == [
        {
            "local_path": "/mnt/ruvps-files",
            "target_host": "10.46.0.6",
            "target_port": 22,
            "username": "ruvps",
            "remote_path": "/files",
        }
    ]
    assert [item.model_dump() for item in exports] == [
        {
            "username": "ruvps",
            "ports": [22],
            "chroot_directory": "/srv/sftp/ruvps",
        }
    ]
    assert [item.model_dump() for item in windows] == [
        {
            "linux_path": "/srv/sftp/ruvps/files",
            "windows_path": "D:\\Downloads\\ru-vps\\files",
        }
    ]
    assert warnings == []


def test_collects_hostname_ipv6_and_custom_sshfs_ports(tmp_path: Path):
    _write_host_files(
        tmp_path,
        """
10 1 0:10 / /mnt/name rw - fuse.sshfs backup@storage.local:/archive rw,port=2222
11 1 0:11 / /mnt/v6 rw - fuse.sshfs user@[fd00::6]:/files rw,sshfs_port=2200
""",
    )

    sshfs, _, _, warnings = collect_mount_topology(str(tmp_path))

    assert [(item.target_host, item.target_port) for item in sshfs] == [
        ("storage.local", 2222),
        ("fd00::6", 2200),
    ]
    assert warnings == []


def test_sftp_chroot_expands_home_and_skips_pattern_matches(tmp_path: Path):
    _write_host_files(
        tmp_path,
        "1 0 0:1 / / rw - ext4 /dev/root rw",
        """
Port 2222
Match User alice
    ChrootDirectory %h
    ForceCommand internal-sftp
Match User backup-*
    ChrootDirectory /srv/backup
    ForceCommand internal-sftp
""",
    )

    _, exports, _, warnings = collect_mount_topology(str(tmp_path))

    assert [item.model_dump() for item in exports] == [
        {
            "username": "alice",
            "ports": [2222],
            "chroot_directory": "/srv/sftp/alice",
        }
    ]
    assert warnings == []


def test_configured_but_unmounted_sshfs_is_not_reported(tmp_path: Path):
    _write_host_files(tmp_path, "1 0 0:1 / / rw - ext4 /dev/root rw")
    (tmp_path / "etc/fstab").write_text(
        "user@10.0.0.2:/files /mnt/files fuse.sshfs defaults 0 0\n",
        encoding="utf-8",
    )

    sshfs, _, _, warnings = collect_mount_topology(str(tmp_path))

    assert sshfs == []
    assert warnings == []


def _node(name: str, ip: str):
    return SimpleNamespace(name=name, expected_vpn_ip=ip)


def test_correlates_complete_mount_across_minion_snapshots():
    initiator = _node("10.46.0.1", "10.46.0.1")
    target = _node("10.46.0.6", "10.46.0.6")
    entries = [
        {
            "node": initiator,
            "stale": False,
            "snapshot": {
                "sshfs_mounts": [
                    {
                        "local_path": "/mnt/ruvps-files",
                        "target_host": "VADIMPC",
                        "target_port": 22,
                        "username": "ruvps",
                        "remote_path": "/files/subtitles",
                    }
                ]
            },
        },
        {
            "node": target,
            "stale": False,
            "snapshot": {
                "host": {"hostname": "VADIMPC"},
                "sftp_exports": [
                    {
                        "username": "ruvps",
                        "ports": [22],
                        "chroot_directory": "/srv/sftp/ruvps",
                    }
                ],
                "windows_path_mappings": [
                    {
                        "linux_path": "/srv/sftp/ruvps/files",
                        "windows_path": "D:\\Downloads\\ru-vps\\files",
                    }
                ],
            },
        },
    ]

    rows = correlate_sshfs_mounts(entries)

    assert len(rows) == 1
    assert rows[0]["initiator_ip"] == "10.46.0.1"
    assert rows[0]["target_ip"] == "10.46.0.6"
    assert rows[0]["initiator_directory"] == "/mnt/ruvps-files"
    assert rows[0]["target_directory"] == "/srv/sftp/ruvps/files/subtitles"
    assert rows[0]["windows_directory"] == "D:\\Downloads\\ru-vps\\files\\subtitles"
    assert rows[0]["target_node"] is target


def test_keeps_partial_row_when_target_snapshot_is_stale():
    initiator = _node("10.46.0.1", "10.46.0.1")
    target = _node("10.46.0.6", "10.46.0.6")
    entries = [
        {
            "node": initiator,
            "stale": False,
            "snapshot": {
                "sshfs_mounts": [
                    {
                        "local_path": "/mnt/files",
                        "target_host": "10.46.0.6",
                        "username": "ruvps",
                        "remote_path": "/files",
                    }
                ]
            },
        },
        {"node": target, "stale": True, "snapshot": {"sftp_exports": []}},
    ]

    rows = correlate_sshfs_mounts(entries)

    assert len(rows) == 1
    assert rows[0]["target_ip"] == "10.46.0.6"
    assert rows[0]["target_directory"] is None
    assert rows[0]["windows_directory"] is None


def test_omits_mounts_from_stale_initiator_snapshot():
    entries = [
        {
            "node": _node("10.46.0.1", "10.46.0.1"),
            "stale": True,
            "snapshot": {
                "sshfs_mounts": [
                    {
                        "local_path": "/mnt/files",
                        "target_host": "10.46.0.6",
                        "remote_path": "/files",
                    }
                ]
            },
        }
    ]

    assert correlate_sshfs_mounts(entries) == []
