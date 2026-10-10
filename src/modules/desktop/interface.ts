export interface DesktopRpcRequest {
  url: string;
  method: "GET" | "POST";
  body?: string;
}
export interface DesktopRpcResponse {
  status: number;
  body: string;
}
export interface DesktopRpcPolicy {
  origin?: string;
  endpoint?: string;
  maxUrlLength?: number;
  maxBodyBytes?: number;
  maxResponseBytes?: number;
}
export interface ShortcutDefinition {
  id: string;
  label: string;
  defaultAccelerator: string;
}
export interface Shortcut extends ShortcutDefinition {
  accelerator: string;
}
