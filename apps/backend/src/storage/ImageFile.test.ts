import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { LocalImageFile } from "./ImageFile.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

describe("LocalImageFile", () => {
  it("measures large image", async () => {
    const image = new LocalImageFile({
      filepath: join(__dirname, "__fixtures__", "long-image.png"),
    });
    await expect(image.getDimensions()).resolves.toEqual({
      height: 20480,
      width: 281,
    });
  });
});
