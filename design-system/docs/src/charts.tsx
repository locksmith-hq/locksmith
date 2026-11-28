// Chart demos: the four a usage dashboard needs, on sample data.
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Line, LineChart, Pie, PieChart, XAxis, YAxis } from "recharts";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@locksmith-hq/ui/chart";

const DAYS = [
  "Nov 14",
  "Nov 15",
  "Nov 16",
  "Nov 17",
  "Nov 18",
  "Nov 19",
  "Nov 20",
  "Nov 21",
  "Nov 22",
  "Nov 23",
  "Nov 24",
  "Nov 25",
  "Nov 26",
  "Nov 27",
];
const RELAYS = [412, 468, 390, 245, 230, 520, 610, 655, 702, 688, 340, 310, 760, 842];
const REFUSED = [6, 9, 4, 2, 3, 11, 8, 14, 9, 7, 3, 2, 12, 5];
const P50 = [34, 36, 33, 31, 30, 38, 41, 40, 39, 37, 32, 31, 42, 38];
const P95 = [88, 96, 84, 72, 70, 110, 128, 121, 117, 104, 79, 76, 133, 112];
const daily = DAYS.map((day, i) => ({
  day,
  relays: RELAYS[i],
  refused: REFUSED[i],
  allowed: RELAYS[i]! - REFUSED[i]!,
  p50: P50[i],
  p95: P95[i],
}));
const agents = [
  { agent: "deploy-bot", calls: 1840, fill: "var(--color-deploy)" },
  { agent: "ci-runner", calls: 1320, fill: "var(--color-ci)" },
  { agent: "support-agent", calls: 760, fill: "var(--color-support)" },
  { agent: "billing-sync", calls: 410, fill: "var(--color-billing)" },
  { agent: "other", calls: 190, fill: "var(--color-other)" },
];

const relayConfig = { relays: { label: "Relays", color: "var(--chart-1)" } } satisfies ChartConfig;
const outcomeConfig = {
  allowed: { label: "Allowed", color: "var(--chart-1)" },
  refused: { label: "Refused", color: "var(--chart-5)" },
} satisfies ChartConfig;
const latencyConfig = {
  p50: { label: "Median", color: "var(--chart-1)" },
  p95: { label: "95th percentile", color: "var(--chart-2)" },
} satisfies ChartConfig;
const agentConfig = {
  calls: { label: "Calls" },
  deploy: { label: "deploy-bot", color: "var(--chart-1)" },
  ci: { label: "ci-runner", color: "var(--chart-2)" },
  support: { label: "support-agent", color: "var(--chart-3)" },
  billing: { label: "billing-sync", color: "var(--chart-4)" },
  other: { label: "other", color: "var(--muted-foreground)" },
} satisfies ChartConfig;

const axis = { tickLine: false, axisLine: false, tickMargin: 8 } as const;

function Panel({ title, note, children }: { title: string; note: string; children: React.ReactNode }) {
  return (
    <figure className="chart-panel">
      <figcaption>
        <b>{title}</b>
        <span>{note}</span>
      </figcaption>
      {children}
    </figure>
  );
}

export function ChartsDemo() {
  return (
    <div className="chart-grid">
      <Panel title="Relays" note="Calls relayed per day, last 14 days">
        <ChartContainer config={relayConfig} className="h-52 w-full">
          <AreaChart data={daily} margin={{ left: 0, right: 8, top: 8 }}>
            <defs>
              <linearGradient id="fill-relays" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-relays)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="var(--color-relays)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="day" {...axis} minTickGap={28} />
            <YAxis {...axis} width={44} />
            <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
            <Area
              dataKey="relays"
              type="monotone"
              stroke="var(--color-relays)"
              strokeWidth={2}
              fill="url(#fill-relays)"
            />
          </AreaChart>
        </ChartContainer>
      </Panel>
      <Panel title="Outcomes" note="Allowed and refused calls per day">
        <ChartContainer config={outcomeConfig} className="h-52 w-full">
          <BarChart data={daily} margin={{ left: 0, right: 8, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="day" {...axis} minTickGap={28} />
            <YAxis {...axis} width={44} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <ChartLegend content={<ChartLegendContent />} />
            <Bar dataKey="allowed" stackId="a" fill="var(--color-allowed)" radius={[0, 0, 2, 2]} />
            <Bar dataKey="refused" stackId="a" fill="var(--color-refused)" radius={[2, 2, 0, 0]} />
          </BarChart>
        </ChartContainer>
      </Panel>
      <Panel title="Relay latency" note="Milliseconds added by the relay">
        <ChartContainer config={latencyConfig} className="h-52 w-full">
          <LineChart data={daily} margin={{ left: 0, right: 8, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="day" {...axis} minTickGap={28} />
            <YAxis {...axis} width={56} unit="ms" />
            <ChartTooltip content={<ChartTooltipContent />} />
            <ChartLegend content={<ChartLegendContent />} />
            <Line dataKey="p50" type="monotone" stroke="var(--color-p50)" strokeWidth={2} dot={false} />
            <Line
              dataKey="p95"
              type="monotone"
              stroke="var(--color-p95)"
              strokeWidth={2}
              dot={false}
              strokeDasharray="4 3"
            />
          </LineChart>
        </ChartContainer>
      </Panel>
      <Panel title="Calls by agent" note="Share of relayed calls this week">
        <ChartContainer config={agentConfig} className="h-52 w-full">
          <PieChart>
            <ChartTooltip content={<ChartTooltipContent nameKey="agent" hideLabel />} />
            <Pie
              data={agents}
              dataKey="calls"
              nameKey="agent"
              innerRadius={52}
              outerRadius={78}
              paddingAngle={2}
              strokeWidth={0}
            />
            <text x="50%" y="48%" textAnchor="middle" className="chart-total">
              4,520
            </text>
            <text x="50%" y="59%" textAnchor="middle" className="chart-total-label">
              calls
            </text>
          </PieChart>
        </ChartContainer>
      </Panel>
    </div>
  );
}
