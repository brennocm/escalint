import { lazy, type ComponentType, type LazyExoticComponent } from 'react';
import type { Indexes } from '../data/indexes';
import type { Route, View } from '../state/route';

/** What every view receives. */
export interface ViewProps {
  readonly ix: Indexes;
  readonly route: Route;
  readonly pseudonyms: boolean;
  readonly navigate: (r: Route) => void;
  /** Change the route in place (filters, selection, camera). */
  readonly update: (patch: (r: Route) => Route) => void;
}

type ViewComponent = LazyExoticComponent<ComponentType<ViewProps>>;

const named = <K extends string>(
  load: () => Promise<Record<K, ComponentType<ViewProps>>>,
  name: K,
): ViewComponent => lazy(() => load().then((m) => ({ default: m[name] })));

/** Views load on demand so the initial bundle stays small. */
export const viewComponents: Record<View, ViewComponent> = {
  overview: named(() => import('./overview/Overview'), 'Overview'),
  atlas: named(() => import('./atlas/Atlas'), 'Atlas'),
  path: named(() => import('./trace/Trace'), 'Trace'),
  reach: named(() => import('./reach/Reach'), 'Reach'),
  exposure: named(() => import('./exposure/Exposure'), 'Exposure'),
  findings: named(() => import('./findings/Findings'), 'Findings'),
  fix: named(() => import('./fix/FixPlan'), 'FixPlan'),
  detect: named(() => import('./detect/Detect'), 'Detect'),
  diff: named(() => import('./diff/Diff'), 'Diff'),
};
