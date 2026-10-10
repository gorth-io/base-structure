import type {
  SupabaseAnyClient,
  UploadInput,
  UploadUtils,
} from "@/utils/interface";

export function createCommonUploadUtils(
  client: SupabaseAnyClient,
): UploadUtils {
  return {
    upload({ bucket, path, fileBody, options }: UploadInput) {
      return client.storage.from(bucket).upload(path, fileBody, options as any);
    },
    upsert({ bucket, path, fileBody, options }: UploadInput) {
      return client.storage.from(bucket).upload(path, fileBody, {
        ...(options ?? {}),
        upsert: true,
      } as any);
    },
    remove(bucket: string, paths: string[]) {
      return client.storage.from(bucket).remove(paths);
    },
    getPublicUrl(bucket: string, path: string) {
      return client.storage.from(bucket).getPublicUrl(path);
    },
    createSignedUrl(bucket: string, path: string, expiresIn: number) {
      return client.storage.from(bucket).createSignedUrl(path, expiresIn);
    },
  };
}

export type { UploadUtils } from "@/utils/interface";
