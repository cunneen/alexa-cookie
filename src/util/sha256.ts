import { type BinaryLike, createHash } from "node:crypto";

export function sha256(buffer: BinaryLike) {
  return createHash("sha256").update(buffer).digest();
}
