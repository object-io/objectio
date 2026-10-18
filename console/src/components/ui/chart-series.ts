import palette from "../../chart-palette.json";

/// Categorical series colours, assigned in a fixed hue order and never cycled
/// (design/chart-palette.json rules). Callers pass the series index so a
/// series keeps its colour when others are toggled off — assigning by position
/// in whatever happens to be visible is how a chart silently changes meaning.
export function seriesColor(index: number, dark = false): string {
  const set = dark ? palette.categorical.dark : palette.categorical.light;
  return set[index % set.length];
}

/// Max series per the same rules; beyond this a chart should switch to small
/// multiples or fold the tail into "Other".
export const MAX_SERIES = 4;
