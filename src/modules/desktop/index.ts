export { createDesktopRpcHandler, createDesktopRpcTransport } from "./rpc";
export {
  normalizeAccelerator,
  shortcutIdentity,
  createShortcutValidator,
} from "./shortcut";
export type {
  DesktopRpcRequest,
  DesktopRpcResponse,
  DesktopRpcPolicy,
  ShortcutDefinition,
  Shortcut,
} from "./interface";
export type { ShortcutPolicy } from "./shortcut";
