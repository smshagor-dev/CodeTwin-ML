import test from "node:test";
import assert from "node:assert/strict";

test("fixture remains executable without package installation", () => {
  assert.equal(2 + 2, 4);
});
