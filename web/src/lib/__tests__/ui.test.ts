import { describe, expect, it } from "vitest";
import type { DeviceRole } from "@/lib/api";
import { deviceRoleLabel } from "@/lib/ui";

describe("deviceRoleLabel", () => {
  it("maps every device role to a non-empty human label", () => {
    const roles: DeviceRole[] = [
      "domain_controller",
      "hypervisor",
      "server",
      "nas",
      "printer",
      "camera",
      "nvr",
      "network_device",
      "industrial_controller",
      "voip_phone",
      "medical_device",
      "media_device",
      "workstation",
      "mobile",
      "iot",
      "unknown",
    ];
    for (const role of roles) {
      expect(deviceRoleLabel[role]).toBeTruthy();
    }
  });

  it("labels the school-critical roles as expected", () => {
    expect(deviceRoleLabel.domain_controller).toBe("Domain Controller");
    expect(deviceRoleLabel.camera).toBe("IP Camera");
    expect(deviceRoleLabel.nas).toBe("NAS");
    expect(deviceRoleLabel.industrial_controller).toBe("Industrial Controller");
  });
});
