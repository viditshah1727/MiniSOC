// A chart with a "Table" toggle: every chart has an accessible table twin,
// so no value is only readable by hovering or by telling colours apart.
import { ChartColumn, Table2 } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { cn } from '../../utils/cn';
import { Button } from '../ui/Button';
import { Card, CardHeader } from '../ui/Card';

export interface ChartTable {
  columns: string[];
  rows: (string | number)[][];
}

interface ChartCardProps {
  title: string;
  subtitle?: string;
  table: ChartTable;
  children: ReactNode;
  /** Dim while newer data loads (keeps the frame instead of flashing). */
  refreshing?: boolean;
  className?: string;
}

export function ChartCard({ title, subtitle, table, children, refreshing = false, className }: ChartCardProps) {
  const [showTable, setShowTable] = useState(false);

  return (
    <Card className={className}>
      <CardHeader
        title={title}
        subtitle={subtitle}
        actions={
          <Button
            size="sm"
            variant="ghost"
            icon={showTable ? ChartColumn : Table2}
            onClick={() => setShowTable((value) => !value)}
            aria-pressed={showTable}
          >
            {showTable ? 'Chart' : 'Table'}
          </Button>
        }
      />
      <div className={cn('p-4 transition-opacity', refreshing && 'opacity-60')}>
        {showTable ? (
          <div className="max-h-80 overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  {table.columns.map((column) => (
                    <th key={column}>{column}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="tabular">
                {table.rows.map((row, index) => (
                  <tr key={index}>
                    {row.map((cell, cellIndex) => (
                      <td key={cellIndex}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          children
        )}
      </div>
    </Card>
  );
}
