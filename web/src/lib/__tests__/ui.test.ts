import { describe, expect, it } from "vitest";
import type { ActionEffort, ActionPriority, DeviceRole } from "@/lib/api";
import {
  actionEffortLabel,
  actionPriorityLabel,
  actionPriorityStyle,
  deviceRoleLabel,
} from "@/lib/ui";

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

describe("action plan maps", () => {
  it("labels and styles every priority", () => {
    const priorities: ActionPriority[] = ["now", "this_week", "soon"];
    for (const p of priorities) {
      expect(actionPriorityLabel[p]).toBeTruthy();
      expect(actionPriorityStyle[p].text).toMatch(/^text-/);
      expect(actionPriorityStyle[p].dot).toMatch(/^bg-/);
    }
    expect(actionPriorityLabel.now).toBe("Now");
    expect(actionPriorityLabel.this_week).toBe("This week");
  });

  it("labels every effort level", () => {
    const efforts: ActionEffort[] = ["quick", "moderate", "project"];
    for (const e of efforts) {
      expect(actionEffortLabel[e]).toBeTruthy();
    }
  });
});
