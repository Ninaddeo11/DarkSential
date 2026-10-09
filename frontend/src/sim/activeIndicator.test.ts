import { describe, expect, it } from "vitest";
import { getActiveIndicator, setActiveIndicator } from "./activeIndicator";

describe("active indicator", () => {
  it("is shared state that trims input and clears on empty values", () => {
    setActiveIndicator(" 8.8.8.8 ");
    expect(getActiveIndicator()).toBe("8.8.8.8");
    setActiveIndicator("   ");
    expect(getActiveIndicator()).toBeNull();
    setActiveIndicator("138.987.22.22");
    setActiveIndicator(null);
    expect(getActiveIndicator()).toBeNull();
  });
});
