// Chart styling in one place. Series colours come from the dataviz palette and
// were validated (CVD separation, contrast >= 3:1) against the card surface.
export const CHART_COLORS = {
  series1: '#3987e5', // categorical slot 1 (blue): events
  series2: '#d95926', // categorical slot 2 (orange): alerts
  surface: '#0e131b', // card background: used for gaps and marker rings
  grid: '#1e2632', // hairline gridlines, one step off the surface
  axis: '#2a3443',
  tick: '#8d99ab', // muted ink
  cursorFill: 'rgba(141, 153, 171, 0.08)',
};

export const AXIS_TICK = { fill: CHART_COLORS.tick, fontSize: 11 };
