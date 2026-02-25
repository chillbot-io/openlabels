import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import {
  HealthTab,
  JobsTab,
  WorkersTab,
  ResourcesTab,
  ThroughputTab,
  ErrorsTab,
  AlertsTab,
  ActivityTab,
} from './tabs/index.ts';

/*
 * System Monitoring — main page.
 *
 * Tab components have been extracted into features/monitoring/tabs/ for
 * maintainability. This file contains only the page layout and tab routing.
 */

export function Component() {
  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">System Monitoring</h1>

      <Tabs defaultValue="health">
        <TabsList aria-label="Monitoring views">
          <TabsTrigger value="health">Health</TabsTrigger>
          <TabsTrigger value="jobs">Jobs</TabsTrigger>
          <TabsTrigger value="workers">Workers</TabsTrigger>
          <TabsTrigger value="resources">Resources</TabsTrigger>
          <TabsTrigger value="throughput">Throughput</TabsTrigger>
          <TabsTrigger value="errors">Errors</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>

        <TabsContent value="health" className="pt-4"><HealthTab /></TabsContent>
        <TabsContent value="jobs" className="pt-4"><JobsTab /></TabsContent>
        <TabsContent value="workers" className="pt-4"><WorkersTab /></TabsContent>
        <TabsContent value="resources" className="pt-4"><ResourcesTab /></TabsContent>
        <TabsContent value="throughput" className="pt-4"><ThroughputTab /></TabsContent>
        <TabsContent value="errors" className="pt-4"><ErrorsTab /></TabsContent>
        <TabsContent value="alerts" className="pt-4"><AlertsTab /></TabsContent>
        <TabsContent value="activity" className="pt-4"><ActivityTab /></TabsContent>
      </Tabs>
    </div>
  );
}
