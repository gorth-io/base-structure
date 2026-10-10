import type { Shortcut } from "./interface";

export function normalizeAccelerator(value: string): string {
  if (!value.trim()) return "";
  const parts = value.split("+").map((part) => part.trim());
  const key = parts.pop()!.replace(/^Arrow/, "");
  if (
    !/^(?:[a-z0-9,./;[\]\\-]|Tab|Space|Plus|Enter|Backspace|Delete|Escape|Up|Down|Left|Right|F(?:[1-9]|1[0-9]|2[0-4]))$/i.test(
      key,
    )
  )
    throw new Error("Choose a letter, number, function key or navigation key.");
  const order = ["CmdOrCtrl", "Ctrl", "Alt", "Shift", "Super"];
  if (
    parts.some((part) => !order.includes(part)) ||
    new Set(parts).size !== parts.length ||
    (!parts.some((part) =>
      ["CmdOrCtrl", "Ctrl", "Alt", "Super"].includes(part),
    ) &&
      !/^F\d+$/i.test(key))
  )
    throw new Error("Use Command/Control, Alt, or a function key.");
  const names = [
    "Tab",
    "Space",
    "Plus",
    "Enter",
    "Backspace",
    "Delete",
    "Escape",
    "Up",
    "Down",
    "Left",
    "Right",
  ];
  return [
    ...order.filter((part) => parts.includes(part)),
    names.find((part) => part.toLowerCase() === key.toLowerCase()) ??
      key.toUpperCase(),
  ].join("+");
}

export function shortcutIdentity(accelerator: string, isMac: boolean): string {
  return accelerator
    .replace("CmdOrCtrl", isMac ? "Super" : "Ctrl")
    .split("+")
    .sort()
    .join("+");
}

export interface ShortcutPolicy {
  isMac: boolean;
  /** Reserved bindings/actions belong to each app, not this package. */
  reserved: readonly string[];
}
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
