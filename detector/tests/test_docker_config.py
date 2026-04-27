"""
test_docker_config.py — Structural tests for Docker Compose and Nginx config.

Sub-task 14.1: Verify docker-compose.yml contains all three services,
               NET_ADMIN capability, and the shared HNG-nginx-logs volume.
               Verify nginx.conf contains the json_combined log format with
               all required fields.

These are static analysis tests — they parse the config files and assert
structural correctness without running any containers.
"""

import os
import re

import pytest
import yaml

# Paths relative to the workspace root (where pytest is run from)
COMPOSE_PATH = "docker-compose.yml"
NGINX_CONF_PATH = "nginx/nginx.conf"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_compose() -> dict:
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


def _read_nginx_conf() -> str:
    with open(NGINX_CONF_PATH) as f:
        return f.read()


# ---------------------------------------------------------------------------
# docker-compose.yml tests
# ---------------------------------------------------------------------------

class TestDockerCompose:
    def test_file_exists(self):
        assert os.path.isfile(COMPOSE_PATH), f"{COMPOSE_PATH} not found"

    def test_has_three_services(self):
        compose = _load_compose()
        services = set(compose.get("services", {}).keys())
        assert "nginx" in services, "nginx service missing"
        assert "nextcloud" in services, "nextcloud service missing"
        assert "detector" in services, "detector service missing"

    def test_nextcloud_uses_correct_image(self):
        compose = _load_compose()
        image = compose["services"]["nextcloud"].get("image", "")
        assert "kefaslungu/hng-nextcloud" in image, (
            f"nextcloud must use kefaslungu/hng-nextcloud, got: {image!r}"
        )

    def test_detector_has_net_admin_capability(self):
        compose = _load_compose()
        cap_add = compose["services"]["detector"].get("cap_add", [])
        assert "NET_ADMIN" in cap_add, (
            "detector service must have NET_ADMIN in cap_add"
        )

    def test_hng_nginx_logs_volume_defined(self):
        compose = _load_compose()
        volumes = compose.get("volumes", {})
        assert "HNG-nginx-logs" in volumes, (
            "Named volume HNG-nginx-logs must be defined at top level"
        )

    def test_nginx_mounts_hng_nginx_logs(self):
        compose = _load_compose()
        nginx_volumes = compose["services"]["nginx"].get("volumes", [])
        volume_strings = [str(v) for v in nginx_volumes]
        assert any("HNG-nginx-logs" in v for v in volume_strings), (
            "nginx service must mount HNG-nginx-logs volume"
        )

    def test_nextcloud_mounts_hng_nginx_logs_readonly(self):
        compose = _load_compose()
        nc_volumes = compose["services"]["nextcloud"].get("volumes", [])
        volume_strings = [str(v) for v in nc_volumes]
        assert any("HNG-nginx-logs" in v for v in volume_strings), (
            "nextcloud service must mount HNG-nginx-logs volume"
        )
        # Must be read-only
        assert any(
            "HNG-nginx-logs" in v and ":ro" in v for v in volume_strings
        ), "nextcloud must mount HNG-nginx-logs as read-only (:ro)"

    def test_detector_mounts_hng_nginx_logs_readonly(self):
        compose = _load_compose()
        det_volumes = compose["services"]["detector"].get("volumes", [])
        volume_strings = [str(v) for v in det_volumes]
        assert any("HNG-nginx-logs" in v for v in volume_strings), (
            "detector service must mount HNG-nginx-logs volume"
        )
        assert any(
            "HNG-nginx-logs" in v and ":ro" in v for v in volume_strings
        ), "detector must mount HNG-nginx-logs as read-only (:ro)"

    def test_detector_exposes_dashboard_port(self):
        compose = _load_compose()
        ports = compose["services"]["detector"].get("ports", [])
        port_strings = [str(p) for p in ports]
        assert any("5000" in p for p in port_strings), (
            "detector must expose port 5000 for the dashboard"
        )

    def test_detector_has_config_yaml_mount(self):
        compose = _load_compose()
        det_volumes = compose["services"]["detector"].get("volumes", [])
        volume_strings = [str(v) for v in det_volumes]
        assert any("config.yaml" in v for v in volume_strings), (
            "detector must bind-mount config.yaml"
        )


# ---------------------------------------------------------------------------
# nginx/nginx.conf tests
# ---------------------------------------------------------------------------

class TestNginxConf:
    def test_file_exists(self):
        assert os.path.isfile(NGINX_CONF_PATH), f"{NGINX_CONF_PATH} not found"

    def test_json_combined_log_format_defined(self):
        conf = _read_nginx_conf()
        assert "json_combined" in conf, (
            "nginx.conf must define a log_format named json_combined"
        )

    def test_log_format_has_source_ip(self):
        conf = _read_nginx_conf()
        assert "source_ip" in conf and "remote_addr" in conf, (
            "json_combined must include source_ip ($remote_addr)"
        )

    def test_log_format_has_timestamp(self):
        conf = _read_nginx_conf()
        assert "timestamp" in conf and "time_iso8601" in conf, (
            "json_combined must include timestamp ($time_iso8601)"
        )

    def test_log_format_has_method(self):
        conf = _read_nginx_conf()
        assert "method" in conf and "request_method" in conf, (
            "json_combined must include method ($request_method)"
        )

    def test_log_format_has_path(self):
        conf = _read_nginx_conf()
        assert "path" in conf and "request_uri" in conf, (
            "json_combined must include path ($request_uri)"
        )

    def test_log_format_has_status(self):
        conf = _read_nginx_conf()
        assert '"status"' in conf, (
            "json_combined must include status field"
        )

    def test_log_format_has_response_size(self):
        conf = _read_nginx_conf()
        assert "response_size" in conf and "body_bytes_sent" in conf, (
            "json_combined must include response_size ($body_bytes_sent)"
        )

    def test_access_log_uses_json_combined(self):
        conf = _read_nginx_conf()
        assert "hng-access.log" in conf and "json_combined" in conf, (
            "access_log must write to hng-access.log using json_combined format"
        )

    def test_real_ip_header_configured(self):
        conf = _read_nginx_conf()
        assert "real_ip_header" in conf and "X-Forwarded-For" in conf, (
            "nginx.conf must set real_ip_header X-Forwarded-For"
        )

    def test_set_real_ip_from_configured(self):
        conf = _read_nginx_conf()
        assert "set_real_ip_from" in conf, (
            "nginx.conf must include set_real_ip_from directive"
        )

    def test_proxies_to_nextcloud(self):
        conf = _read_nginx_conf()
        assert "nextcloud" in conf and "proxy_pass" in conf, (
            "nginx.conf must proxy traffic to the nextcloud upstream"
        )
