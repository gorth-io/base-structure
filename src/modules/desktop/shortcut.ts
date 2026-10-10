import type { Shortcut } from "@/modules/desktop/interface";
import { normalizeAccelerator, shortcutIdentity } from "@/utils/formatter";
import type { ShortcutPolicy } from "@/utils/interface";

export function createShortcutValidator(policy: ShortcutPolicy) {
  const reserved = new Set(
    policy.reserved.map((value) =>
      shortcutIdentity(normalizeAccelerator(value), policy.isMac),
    ),
  );
  return function validateShortcutChange(
    shortcuts: readonly Shortcut[],
    id: string,
    value: string,
  ) {
    if (!shortcuts.some((shortcut) => shortcut.id === id))
      throw new Error("Unknown shortcut.");
    const accelerator = normalizeAccelerator(value);
    const identity = shortcutIdentity(accelerator, policy.isMac);
    const parts = identity.split("+");
    if (new Set(parts).size !== parts.length)
      throw new Error("Duplicate shortcut modifier.");
    if (
      accelerator &&
      shortcuts.some(
        (shortcut) =>
          shortcut.id !== id &&
          shortcutIdentity(
            normalizeAccelerator(shortcut.accelerator),
            policy.isMac,
          ) === identity,
      )
    )
      throw new Error("This shortcut is already assigned.");
    if (accelerator && reserved.has(identity))
      throw new Error(
        "This shortcut is reserved by the application or operating system.",
      );
    return accelerator;
  };
}

export type { ShortcutPolicy } from "@/utils/interface";

export { normalizeAccelerator, shortcutIdentity } from "@/utils/formatter";
