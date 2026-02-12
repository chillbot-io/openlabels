import { useState } from 'react';
import { Download } from 'lucide-react';
import { useQuerySchema, useExecuteQuery, useAIQuery } from '@/api/hooks/use-query.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import { downloadBlob } from '@/api/endpoints/export.ts';
import type { QueryResult } from '@/api/types.ts';

function ResultsGrid({ result }: { result: QueryResult }) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-[var(--muted)]">
          <tr>
            {result.columns.map((col) => (
              <th key={col} className="px-4 py-2 text-left font-medium">{col}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {result.rows.map((row, i) => (
            <tr key={i} className="border-t">
              {row.map((cell, j) => (
                <td key={j} className="px-4 py-2 font-mono text-xs">{String(cell ?? '')}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex items-center justify-between border-t px-4 py-2 text-xs text-[var(--muted-foreground)]">
        <span>{result.row_count} rows &middot; {result.execution_time_ms}ms</span>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            const csv = [result.columns.join(','), ...result.rows.map((r) => r.map((c) => JSON.stringify(c ?? '')).join(','))].join('\n');
            downloadBlob(new Blob([csv], { type: 'text/csv' }), `query-results-${Date.now()}.csv`);
          }}
        >
          <Download className="mr-1 h-3.5 w-3.5" /> Export CSV
        </Button>
      </div>
    </div>
  );
}

function SQLEditor() {
  const [sql, setSql] = useState('SELECT * FROM scan_results LIMIT 100');
  const executeQuery = useExecuteQuery();
  const addToast = useUIStore((s) => s.addToast);
  const schema = useQuerySchema();

  const handleExecute = () => {
    executeQuery.mutate(sql, {
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-4">
        <div className="flex-1 space-y-2">
          <textarea
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            className="h-40 w-full rounded-md border bg-[var(--muted)] p-3 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
            placeholder="Enter SQL query..."
          />
          <Button onClick={handleExecute} disabled={executeQuery.isPending || !sql.trim()}>
            {executeQuery.isPending ? 'Executing...' : 'Run Query'}
          </Button>
        </div>
        <div className="w-48">
          <p className="mb-2 text-xs font-semibold text-[var(--muted-foreground)]">Tables</p>
          {schema.isLoading ? (
            <Skeleton className="h-32" />
          ) : (
            <div className="space-y-1 text-xs">
              {(schema.data?.tables ?? []).map((table) => (
                <details key={table.name}>
                  <summary className="cursor-pointer rounded px-1 py-0.5 hover:bg-[var(--muted)]">
                    {table.name}
                  </summary>
                  <div className="ml-3 space-y-0.5 text-[var(--muted-foreground)]">
                    {table.columns.map((col) => (
                      <p key={col.name}>{col.name} <span className="opacity-50">({col.type})</span></p>
                    ))}
                  </div>
                </details>
              ))}
            </div>
          )}
        </div>
      </div>

      {executeQuery.data && <ResultsGrid result={executeQuery.data} />}
    </div>
  );
}

function AIAssistant() {
  const [question, setQuestion] = useState('');
  const aiQuery = useAIQuery();
  const addToast = useUIStore((s) => s.addToast);

  const handleAsk = () => {
    aiQuery.mutate({ question, execute: true }, {
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Show me all files with SSN in the Finance share from last week"
          className="flex-1"
          onKeyDown={(e) => e.key === 'Enter' && handleAsk()}
        />
        <Button onClick={handleAsk} disabled={aiQuery.isPending || !question.trim()}>
          {aiQuery.isPending ? 'Thinking...' : 'Ask'}
        </Button>
      </div>

      {aiQuery.data && (
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-sm">Generated SQL</CardTitle></CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-md bg-[var(--muted)] p-3 text-xs">{aiQuery.data.sql}</pre>
              <p className="mt-2 text-sm text-[var(--muted-foreground)]">{aiQuery.data.explanation}</p>
            </CardContent>
          </Card>
          {aiQuery.data.result && <ResultsGrid result={aiQuery.data.result} />}
        </div>
      )}
    </div>
  );
}

export function Component() {
  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Reports</h1>

      <Tabs defaultValue="sql">
        <TabsList>
          <TabsTrigger value="sql">SQL Editor</TabsTrigger>
          <TabsTrigger value="ai">AI Assistant</TabsTrigger>
        </TabsList>

        <TabsContent value="sql" className="pt-4">
          <SQLEditor />
        </TabsContent>
        <TabsContent value="ai" className="pt-4">
          <AIAssistant />
        </TabsContent>
      </Tabs>
    </div>
  );
}
