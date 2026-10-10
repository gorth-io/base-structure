export type {
  DesktopRpcPolicy,
  DesktopRpcRequest,
  DesktopRpcResponse,
  Shortcut,
  ShortcutDefinition,
} from "@/modules/desktop/interface";
export {
  createDesktopRpcHandler,
  createDesktopRpcTransport,
} from "@/modules/desktop/rpc";
export {
  createShortcutValidator,
  normalizeAccelerator,
  shortcutIdentity,
} from "@/modules/desktop/shortcut";
export type { ShortcutPolicy } from "@/modules/desktop/shortcut";
