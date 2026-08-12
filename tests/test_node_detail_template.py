from types import SimpleNamespace

from cozy_network_manager.app.ui.templates import templates


def test_node_detail_hides_empty_snapshot_sections():
    request = SimpleNamespace(
        state=SimpleNamespace(auth_configured=False, authenticated=False)
    )
    node = SimpleNamespace(
        name="phone",
        expected_vpn_ip="10.46.0.8",
        os_override=None,
        manual_tags=[],
        configured_tags=[],
        notes="",
    )
    snapshot = SimpleNamespace(
        collected_at="now",
        snapshot={
            "host": {
                "hostname": "phone",
                "public_ipv4": None,
                "os_name": "Linux",
                "os_version": "",
                "kernel_version": "kernel",
                "architecture": "arm64",
            },
            "public_interfaces": [],
            "wireguard": [],
            "docker_containers": [],
        },
    )

    html = templates.env.get_template("node_detail.html").render(
        request=request,
        node=node,
        device=None,
        snapshot=snapshot,
        snapshot_stale=False,
        sshfs_mount_rows=[],
    )

    assert "<h2>Manual metadata</h2>" in html
    assert "<h2>Status</h2>" in html
    assert "<h2>SSHFS mounts</h2>" not in html
    assert "<h2>Public interfaces</h2>" not in html
    assert "<h2>WireGuard</h2>" not in html
    assert "<h2>Docker containers</h2>" not in html


def test_node_detail_renders_head_status_without_a_minion_snapshot():
    request = SimpleNamespace(
        state=SimpleNamespace(auth_configured=False, authenticated=False)
    )
    node = SimpleNamespace(
        name="phone",
        expected_vpn_ip="10.46.0.8",
        os_override=None,
        manual_tags=["mobile"],
        configured_tags=[],
        notes="",
    )
    device = SimpleNamespace(
        name="phone",
        current_public_ip="203.0.113.8",
        wg_connected=True,
        pingable=False,
        minion_available=False,
        last_checked_at="now",
    )

    html = templates.env.get_template("node_detail.html").render(
        request=request,
        node=node,
        device=device,
        snapshot=None,
        snapshot_stale=False,
        sshfs_mount_rows=[],
    )

    assert "<h2>Manual metadata</h2>" in html
    assert 'value="mobile"' in html
    assert "<h2>Status</h2>" in html
    assert "203.0.113.8" in html
    assert "<h2>SSHFS mounts</h2>" not in html
    assert "<h2>Public interfaces</h2>" not in html
    assert "<h2>WireGuard</h2>" not in html
    assert "<h2>Docker containers</h2>" not in html
