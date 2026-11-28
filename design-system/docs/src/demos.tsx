// One live demo per page, keyed by package folder. Each is the smallest honest use of the component.
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  Bot,
  ChevronsUpDown,
  Copy,
  KeyRound,
  Lock,
  LockOpen,
  Bold,
  Plus,
  Search,
  Settings,
  ShieldAlert,
  Trash2,
  Users,
} from "lucide-react";
import { toast } from "sonner";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@locksmith-hq/ui/accordion";
import { ActionBar } from "@locksmith-hq/ui/action-bar";
import { Alert, AlertDescription, AlertTitle } from "@locksmith-hq/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@locksmith-hq/ui/alert-dialog";
import { Avatar, AvatarFallback } from "@locksmith-hq/ui/avatar";
import { Badge } from "@locksmith-hq/ui/badge";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@locksmith-hq/ui/breadcrumb";
import { Button } from "@locksmith-hq/ui/button";
import { ButtonGroup } from "@locksmith-hq/ui/button-group";
import { Calendar } from "@locksmith-hq/ui/calendar";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@locksmith-hq/ui/card";
import { Checkbox } from "@locksmith-hq/ui/checkbox";
import { Chip } from "@locksmith-hq/ui/chip";
import { CodeBlock, CodeBlockActions, CodeBlockContent, CodeBlockCopyButton } from "@locksmith-hq/ui/code-block";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@locksmith-hq/ui/collapsible";
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from "@locksmith-hq/ui/combobox";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@locksmith-hq/ui/command";
import { ConfirmDialog } from "@locksmith-hq/ui/confirm-dialog";
import { CopyButton } from "@locksmith-hq/ui/copy-button";
import { CopyableId } from "@locksmith-hq/ui/copyable-id";
import { DataTable } from "@locksmith-hq/ui/data-table";
import { DatePicker } from "@locksmith-hq/ui/date-picker";
import { DateRangePicker } from "@locksmith-hq/ui/date-range-picker";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@locksmith-hq/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from "@locksmith-hq/ui/dropdown-menu";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@locksmith-hq/ui/empty";
import { EmptyState } from "@locksmith-hq/ui/empty-state";
import { PlanBadge } from "@locksmith-hq/ui/plan-badge";
import { UpgradeNotice } from "@locksmith-hq/ui/upgrade-notice";
import { ColorsPage, IconsPage } from "./foundations";
import { ChartsDemo } from "./charts";
import { KebabButton } from "@locksmith-hq/ui/kebab-button";
import { Combination } from "@locksmith-hq/ui/combination";
import { HoldToConfirm } from "@locksmith-hq/ui/hold-to-confirm";
import { SlideToUnlock } from "@locksmith-hq/ui/slide-to-unlock";
import { LeaseTimer } from "@locksmith-hq/ui/lease-timer";
import { RelayPath } from "@locksmith-hq/ui/relay-path";
import { Facts } from "@locksmith-hq/ui/facts";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@locksmith-hq/ui/field";
import { FileUpload } from "@locksmith-hq/ui/file-upload";
import { FilterBar, type FilterValue } from "@locksmith-hq/ui/filter-bar";
import { Input } from "@locksmith-hq/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@locksmith-hq/ui/input-group";
import { Kbd, KbdGroup } from "@locksmith-hq/ui/kbd";
import { Label } from "@locksmith-hq/ui/label";
import { LabelsProvider } from "@locksmith-hq/ui/labels";
import { Link } from "@locksmith-hq/ui/link";
import { LiveDot } from "@locksmith-hq/ui/live-dot";
import { Loader } from "@locksmith-hq/ui/loader";
import { Mark } from "@locksmith-hq/ui/mark";
import { Meter } from "@locksmith-hq/ui/meter";
import { NumberField } from "@locksmith-hq/ui/number-field";
import { PageHeader } from "@locksmith-hq/ui/page-header";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@locksmith-hq/ui/pagination";
import { PasswordField } from "@locksmith-hq/ui/password-field";
import { Pill } from "@locksmith-hq/ui/pill";
import { Popover, PopoverContent, PopoverTrigger } from "@locksmith-hq/ui/popover";
import { Progress, ProgressRing, ProgressRow } from "@locksmith-hq/ui/progress";
import { RadioGroup, RadioGroupItem } from "@locksmith-hq/ui/radio-group";
import { ScopeChip } from "@locksmith-hq/ui/scope-chip";
import { Secret } from "@locksmith-hq/ui/secret";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@locksmith-hq/ui/select";
import { Separator } from "@locksmith-hq/ui/separator";
import { SettingRow } from "@locksmith-hq/ui/setting-row";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@locksmith-hq/ui/sheet";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@locksmith-hq/ui/sidebar";
import { Skeleton } from "@locksmith-hq/ui/skeleton";
import { Spinner } from "@locksmith-hq/ui/spinner";
import { Stat } from "@locksmith-hq/ui/stat";
import { Stepper } from "@locksmith-hq/ui/stepper";
import { Switch } from "@locksmith-hq/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@locksmith-hq/ui/tabs";
import { TagsInput } from "@locksmith-hq/ui/tags-input";
import { Textarea } from "@locksmith-hq/ui/textarea";
import { Timeline } from "@locksmith-hq/ui/timeline";
import { Toggle } from "@locksmith-hq/ui/toggle";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@locksmith-hq/ui/tooltip";
import { Tumblers } from "@locksmith-hq/ui/tumblers";
import { Wordmark } from "@locksmith-hq/ui/wordmark";

const Row = (p: { children: ReactNode }) => <div className="demo-row">{p.children}</div>;
const Col = (p: { children: ReactNode }) => <div className="demo-col">{p.children}</div>;
const Muted = (p: { children: ReactNode }) => <span className="text-muted-foreground">{p.children}</span>;

function MarkDemo() {
  const [open, set] = useState(false);
  return (
    <Row>
      <Mark size={56} open={open} />
      <Mark small size={28} open={open} />
      <Mark small mono size={28} open={open} />
      <Button size="sm" variant="outline" onClick={() => set(!open)}>
        {open ? <Lock /> : <KeyRound />} {open ? "Lock" : "Unlock"}
      </Button>
    </Row>
  );
}

const AGENTS = [
  { id: "agt_01", agent: "deploy-bot", env: "production", state: "Live", calls: 1204, used: "2 min ago", age: 2 },
  { id: "agt_02", agent: "billing-sync", env: "production", state: "Live", calls: 318, used: "3 hours ago", age: 180 },
  { id: "agt_03", agent: "support-triage", env: "staging", state: "Paused", calls: 57, used: "Yesterday", age: 1500 },
  { id: "agt_04", agent: "ci-runner-10", env: "development", state: "Live", calls: 9120, used: "Just now", age: 0 },
  {
    id: "agt_05",
    agent: "ci-runner-2",
    env: "development",
    state: "Revoked",
    calls: 0,
    used: "12 days ago",
    age: 17280,
  },
];
const tone = (s: string) => (s === "Live" ? "live" : s === "Paused" ? "warning" : "danger");

// The list parts together, as a page would use them: filters narrow the rows, the header sorts them,
// and a selection brings up the action bar.
function ListDemo() {
  const [filters, setFilters] = useState<FilterValue>({});
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [ask, setAsk] = useState(false);
  // The demo's controls: which state the table is in, and which options are on.
  const [state, setState] = useState<"data" | "loading" | "empty">("data");
  const [selectable, setSelectable] = useState(true);
  const [sticky, setSticky] = useState(true);
  const reload = () => {
    setState("loading");
    setTimeout(() => setState("data"), 1800);
  };
  const rows = (state === "empty" ? [] : AGENTS).filter(
    (a) =>
      a.agent.includes(q.trim().toLowerCase()) &&
      (!filters.env || filters.env.includes(a.env)) &&
      (!filters.state || filters.state.includes(a.state)),
  );
  return (
    <Col>
      <div className="demo-controls">
        <ToggleGroup
          type="single"
          value={state}
          onValueChange={(v) => v && setState(v as typeof state)}
          aria-label="Table state"
        >
          <ToggleGroupItem value="data">Data</ToggleGroupItem>
          <ToggleGroupItem value="loading">Loading</ToggleGroupItem>
          <ToggleGroupItem value="empty">Empty</ToggleGroupItem>
        </ToggleGroup>
        <Label>
          <Switch data-plain checked={selectable} onCheckedChange={setSelectable} /> Selectable
        </Label>
        <Label>
          <Switch data-plain checked={sticky} onCheckedChange={setSticky} /> Sticky header
        </Label>
        <Button size="sm" variant="outline" onClick={reload}>
          Reload
        </Button>
      </div>
      <FilterBar
        filters={[
          { key: "env", label: "Environment", options: ["production", "staging", "development"] },
          { key: "state", label: "State", options: ["Live", "Paused", "Revoked"] },
        ]}
        onChange={setFilters}
      >
        <Input
          className="h-8 w-60"
          aria-label="Filter agents"
          placeholder="Filter by name"
          onChange={(e) => setQ(e.target.value)}
        />
      </FilterBar>
      <DataTable
        loading={state === "loading"}
        selectable={selectable}
        selected={picked}
        onSelectionChange={setPicked}
        defaultSort={{ key: "agent", dir: "asc" }}
        maxHeight={sticky ? 236 : undefined}
        columns={[
          { key: "agent", label: "Agent", sortable: true },
          { key: "env", label: "Environment", sortable: true, muted: true },
          { key: "state", label: "State", sortable: true, sortBy: (r) => AGENTS.find((a) => a.id === r.id)!.state },
          {
            key: "used",
            label: "Last used",
            sortable: true,
            muted: true,
            sortBy: (r) => AGENTS.find((a) => a.id === r.id)!.age,
          },
          { key: "calls", label: "Calls", num: true, mono: true, sortable: true },
        ]}
        rows={rows.map((a) => ({
          id: a.id,
          agent: a.agent,
          env: a.env,
          used: a.used,
          calls: a.calls,
          bad: a.state === "Revoked",
          state: <Pill tone={tone(a.state)}>{a.state}</Pill>,
        }))}
        empty={
          state === "empty" ? (
            <EmptyState size="compact" title="No agents yet">
              Register one, then give it a grant.
            </EmptyState>
          ) : (
            <EmptyState size="compact" kind="no-results" title="No agents match">
              Clear a filter to see more.
            </EmptyState>
          )
        }
      />
      <ActionBar count={picked.length} noun="agents" onClear={() => setPicked([])}>
        <Button size="sm" variant="outline">
          <KeyRound /> Rotate keys
        </Button>
        <Button size="sm" variant="destructive" onClick={() => setAsk(true)}>
          Revoke
        </Button>
      </ActionBar>
      <ConfirmDialog
        open={ask}
        onClose={() => setAsk(false)}
        onConfirm={() => setPicked([])}
        danger
        confirmLabel="Revoke"
        title={`Revoke ${picked.length} agent${picked.length === 1 ? "" : "s"}?`}
      >
        They lose access at once. You can grant it again, but running sessions end.
      </ConfirmDialog>
    </Col>
  );
}

function ConfirmDemo() {
  const [open, set] = useState<"" | "plain" | "typed">("");
  return (
    <Row>
      <Button variant="outline" onClick={() => set("plain")}>
        Pause agent
      </Button>
      <Button variant="destructive" onClick={() => set("typed")}>
        Delete project
      </Button>
      <ConfirmDialog
        open={open === "plain"}
        onClose={() => set("")}
        onConfirm={() => {}}
        title="Pause deploy-bot?"
        confirmLabel="Pause"
      >
        Its requests are refused until you resume it. Nothing is deleted.
      </ConfirmDialog>
      <ConfirmDialog
        open={open === "typed"}
        onClose={() => set("")}
        onConfirm={() => {}}
        danger
        title="Delete the payments project?"
        confirmLabel="Delete project"
        confirmText="payments"
      >
        This deletes 8 secrets and revokes 3 grants. It cannot be undone.
      </ConfirmDialog>
    </Row>
  );
}

function ActionBarDemo() {
  const [n, setN] = useState(3);
  return (
    <Col>
      <ActionBar count={n} noun="secrets" onClear={() => setN(0)}>
        <Button size="sm" variant="outline">
          <KeyRound /> Rotate
        </Button>
        <Button size="sm" variant="destructive">
          Delete
        </Button>
      </ActionBar>
      {n ? null : (
        <Button size="sm" variant="outline" onClick={() => setN(3)}>
          Select three again
        </Button>
      )}
    </Col>
  );
}

function StepperDemo() {
  const steps = ["Create a project", "Add a secret", "Register an agent", "Grant access"];
  const [at, set] = useState(1);
  return (
    <Col>
      <Stepper steps={steps} current={at} label="Set up" />
      <Row>
        <Button size="sm" variant="outline" disabled={at === 0} onClick={() => set(at - 1)}>
          Back
        </Button>
        <Button size="sm" disabled={at >= steps.length} onClick={() => set(at + 1)}>
          {at >= steps.length - 1 ? "Finish" : "Next"}
        </Button>
      </Row>
    </Col>
  );
}

function CalendarDemo() {
  const [day, setDay] = useState<Date | undefined>(new Date());
  return <Calendar mode="single" selected={day} onSelect={setDay} className="rounded-lg border" />;
}

const PROJECTS = ["payments", "billing", "identity", "notifications", "search"];
const CMD = "smith init --project payments";
const SNIPPET_TSX = `import { relay } from "@locksmith-hq/sdk";

// The agent never sees the key: Locksmith adds it on the way out.
export async function listCharges(limit = 10) {
  const res = await relay("stripe/charges", { method: "GET", query: { limit } });
  return res.ok ? res.json() : null;
}`;
const SNIPPET_JSON = `{
  "grant": "stripe/charges",
  "agent": "deploy-bot",
  "level": "read",
  "ttlSeconds": 3600,
  "approved": true
}`;
const code = (text: string, language = "bash") => (
  <CodeBlock>
    <CodeBlockContent language={language}>{text}</CodeBlockContent>
    <CodeBlockActions>
      <CodeBlockCopyButton value={text} />
    </CodeBlockActions>
  </CodeBlock>
);

// [what it is, the demo]. A page without an entry here shows its API only.
function CombinationDemo() {
  const [code, setCode] = useState("482 915");
  const [count, setCount] = useState(128);
  const roll = () => {
    const n = String(Math.floor(Math.random() * 1e6)).padStart(6, "0");
    setCode(`${n.slice(0, 3)} ${n.slice(3)}`);
    setCount((c) => c + 1 + Math.floor(Math.random() * 40));
  };
  return (
    <Col>
      <Row>
        <Combination value={code} />
        <Button variant="outline" onClick={roll}>
          New code
        </Button>
      </Row>
      <Row>
        <Combination value={count} digits={4} style={{ fontSize: 18 }} />
        <Muted>relays today</Muted>
      </Row>
    </Col>
  );
}

function HoldDemo() {
  const [n, setN] = useState(0);
  return (
    <Row>
      <HoldToConfirm onConfirm={() => setN(n + 1)}>
        <Trash2 /> Hold to revoke
      </HoldToConfirm>
      <HoldToConfirm variant="outline" duration={700} onConfirm={() => setN(n + 1)}>
        Hold to rotate
      </HoldToConfirm>
      <Muted>{n ? `Confirmed ${n} time${n === 1 ? "" : "s"}.` : "A click does nothing. Hold it."}</Muted>
    </Row>
  );
}

function SlideDemo() {
  const [round, setRound] = useState(0);
  const [open, setOpen] = useState(false);
  return (
    <Col>
      <SlideToUnlock
        key={round}
        label="Slide to unseal the vault"
        doneLabel="Unsealed"
        onUnlock={() => setOpen(true)}
      />
      <Row>
        <Button
          variant="outline"
          size="sm"
          disabled={!open}
          onClick={() => {
            setOpen(false);
            setRound(round + 1);
          }}
        >
          Lock it again
        </Button>
        <SlideToUnlock disabled style={{ width: 200 }} label="Not allowed" />
      </Row>
    </Col>
  );
}

function LeaseDemo() {
  const [start] = useState(() => Date.now());
  const MIN = 60_000;
  return (
    <Row>
      <LeaseTimer label="Database credential" expiresAt={start + 14 * MIN} total={15 * MIN} />
      <LeaseTimer label="AWS session" expiresAt={start + 4 * MIN} total={15 * MIN} />
      <LeaseTimer label="Deploy token" expiresAt={start + 40_000} total={5 * MIN} />
      <LeaseTimer label="Old token" expiresAt={start - 1000} total={5 * MIN} />
      <LeaseTimer label="Signing key" size={36} expiresAt={start + 5 * 60 * MIN} total={8 * 60 * MIN} />
    </Row>
  );
}

function ProgressDemo() {
  const [value, setValue] = useState(32);
  const [running, setRunning] = useState(false);
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setValue((v) => Math.min(100, v + 4)), 220);
    return () => clearInterval(t);
  }, [running]);
  useEffect(() => {
    if (value >= 100) setRunning(false);
  }, [value]);
  return (
    <Col>
      <div className="demo-controls">
        <Button
          size="sm"
          variant="outline"
          onClick={() => (value >= 100 ? (setValue(0), setRunning(true)) : setRunning(!running))}
        >
          {value >= 100 ? "Run again" : running ? "Pause" : "Run"}
        </Button>
        <Button size="sm" variant="ghost" onClick={() => (setRunning(false), setValue(0))}>
          Reset
        </Button>
      </div>
      <ProgressRow label="Rotating keys" value={value} detail={`${Math.round(value / 4)} of 25 keys`} />
      <ProgressRow label="Checking grants" detail="Counting what is in scope" />
      <ProgressRow label="Storage" value={84} tone="warning" detail="4.2 of 5 GB" />
      <ProgressRow label="Import" value={46} tone="danger" detail="Stopped: 3 secrets were refused." />
      <div className="demo-variants">
        <span>Default</span>
        <Progress value={value} aria-label="Default" />
        <span>Small</span>
        <Progress value={value} data-size="sm" aria-label="Small" />
        <span>Large</span>
        <Progress value={value} data-size="lg" aria-label="Large" />
        <span>Line</span>
        <Progress value={value} data-variant="line" aria-label="Line" />
        <span>Notched</span>
        <Progress value={value} data-variant="notched" aria-label="Notched" />
        <span>Ring</span>
        <Row>
          <ProgressRing value={value} />
          <ProgressRing value={value} size={28} />
          <ProgressRing value={value} size={40} tone="live" />
          <ProgressRing size={28} label="Working" />
        </Row>
      </div>
    </Col>
  );
}

function ToggleDemo() {
  const [shown, setShown] = useState(false);
  return (
    <Row>
      <Toggle variant="outline" pressed={shown} onPressedChange={setShown}>
        {shown ? <LockOpen /> : <Lock />} Show values
      </Toggle>
      <Toggle aria-label="Bold" defaultPressed>
        <Bold />
      </Toggle>
      <Muted>{shown ? "Values are shown." : "Values are sealed."}</Muted>
    </Row>
  );
}

export const DEMOS: Record<string, [string, ReactNode]> = {
  mark: [
    "The vault dial: a ring of six bolts round a keyhole. The bolts are the brand colour; `mono` draws them in the text colour, for a mark inline in text or one whose colour carries a state. Unlocking turns the ring a sixth of a turn and draws the bolts in.",
    <MarkDemo />,
  ],
  colors: [
    "Every colour is a CSS variable with a light and a dark value. Use the variable, never the hex. Click one to copy it.",
    <ColorsPage />,
  ],
  icons: ["The kit draws icons from lucide-react. Every icon in it is here; click one to copy its tag.", <IconsPage />],
  wordmark: [
    "The name in two weights: LOCK heavy, SMITH light. The bar and key tooth under LOCK are the ones the Tabs indicator carries. Plain and mono are for small or one-colour places; with the mark it is the full logo.",
    <div className="demo-variants">
      <span>Default</span>
      <Row>
        <Wordmark size={36} />
        <Wordmark size={22} />
        <Wordmark />
      </Row>
      <span>Plain</span>
      <Row>
        <Wordmark variant="plain" size={22} />
        <Wordmark variant="plain" />
        <Wordmark variant="plain" size={11} />
      </Row>
      <span>Mono</span>
      <Row>
        <Wordmark variant="mono" size={22} />
        <span className="rounded-md bg-(--brand) px-4 py-3 text-(--brand-foreground)">
          <Wordmark variant="mono" />
        </span>
      </Row>
      <span>With mark, left</span>
      <Row>
        <Wordmark mark="left" size={22} />
        <Wordmark mark="left" />
      </Row>
      <span>With mark, top</span>
      <Row>
        <Wordmark mark="top" size={18} />
        <Wordmark mark="top" variant="plain" size={13} />
      </Row>
    </div>,
  ],
  button: [
    "Raised: it stands up on a lip and sinks when pressed. One primary per view; destructive for what cannot be undone.",
    <Row>
      <Button>Grant access</Button>
      <Button variant="outline">
        <KeyRound /> Rotate now
      </Button>
      <Button variant="destructive">
        <Trash2 /> Revoke
      </Button>
      <Button variant="ghost">Cancel</Button>
      <Button variant="link">View the grant</Button>
      <Button size="sm" variant="outline">
        <Plus /> Add
      </Button>
      <Button size="icon" variant="outline" aria-label="Rotate">
        <KeyRound />
      </Button>
      <Button disabled>
        <Spinner /> Sealing
      </Button>
    </Row>,
  ],
  "kebab-button": [
    "The three-dot button for more actions. Vertical at the end of a row or card, horizontal in a toolbar. It is a Button, so it works as a menu trigger.",
    <Row>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <KebabButton label="Actions for deploy-bot" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuItem>Rotate key</DropdownMenuItem>
          <DropdownMenuItem>View grants</DropdownMenuItem>
          <DropdownMenuItem variant="destructive">Revoke</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <KebabButton orientation="horizontal" label="More" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuItem>Duplicate</DropdownMenuItem>
          <DropdownMenuItem>Export</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <KebabButton variant="outline" />
      <KebabButton orientation="horizontal" variant="outline" />
      <KebabButton size="icon" variant="outline" />
      <KebabButton disabled />
    </Row>,
  ],
  "button-group": [
    "Buttons that belong to one decision, joined.",
    <ButtonGroup>
      <Button variant="outline">Day</Button>
      <Button variant="outline">Week</Button>
      <Button variant="outline">Month</Button>
    </ButtonGroup>,
  ],
  field: [
    "A label, a control, and a hint or an error. Wrap every form control in one.",
    <FieldGroup className="max-w-xl flex-row flex-wrap gap-4">
      <Field className="w-64">
        <FieldLabel htmlFor="f-name">Agent name</FieldLabel>
        <Input id="f-name" defaultValue="deploy-bot" />
        <FieldDescription>Shown in the audit log.</FieldDescription>
      </Field>
      <Field className="w-64" data-invalid>
        <FieldLabel htmlFor="f-scope">Scope</FieldLabel>
        <Input id="f-scope" className="font-mono" defaultValue="charges:rea" aria-invalid />
        <FieldError>This scope does not exist.</FieldError>
      </Field>
    </FieldGroup>,
  ],
  input: [
    "A recessed well: what you fill is cut in.",
    <Row>
      <Input className="w-64" placeholder="api.example.com" />
      <Input className="w-64 font-mono" aria-label="Key name" defaultValue="STRIPE_SECRET_KEY" />
      <Input className="w-64" disabled placeholder="Disabled" />
    </Row>,
  ],
  "input-group": [
    "A well with something set into its end: an icon, a unit, a button.",
    <Row>
      <InputGroup className="w-72">
        <InputGroupAddon>
          <Search />
        </InputGroupAddon>
        <InputGroupInput placeholder="Filter by key" aria-label="Filter secrets" />
      </InputGroup>
      <InputGroup className="w-48">
        <InputGroupInput defaultValue="30" aria-label="Rotate every" />
        <InputGroupAddon align="inline-end">days</InputGroupAddon>
      </InputGroup>
    </Row>,
  ],
  textarea: [
    "A taller well, for notes and pasted keys.",
    <Textarea className="max-w-md" placeholder="Why does this agent need access?" />,
  ],
  label: [
    "The name of a control. Clicking it focuses the control.",
    <Row>
      <Checkbox id="l-notify" defaultChecked />
      <Label htmlFor="l-notify">Notify me before a key expires</Label>
    </Row>,
  ],
  "number-field": [
    "A number in a well with a step button on each side. Arrow keys step too.",
    <Row>
      <NumberField label="Rotate every (days)" defaultValue={30} min={1} max={365} />
      <NumberField label="Max sessions" defaultValue={5} min={0} step={5} help="0 means no limit." />
      <NumberField label="Retries" defaultValue={12} max={10} required error="10 at most." />
      <NumberField label="Seats" defaultValue={3} disabled help="Set by your plan." />
    </Row>,
  ],
  "password-field": [
    "For typing or pasting a secret. Masked until its lock is opened; never spell-checked.",
    <Row>
      <PasswordField label="Secret value" placeholder="Paste the value" help="Sealed as soon as you save." />
      <PasswordField label="API key" defaultValue="example-key-51NqT8xKf2" error="This key was revoked." />
      <PasswordField
        label="Signing key"
        defaultValue="example-key-51NqT8xKf2"
        disabled
        help="Managed by the gateway."
      />
    </Row>,
  ],
  "tags-input": [
    "Values you type, kept as chips: hosts, IP ranges, scopes. Enter or a comma adds one; paste a list to add many.",
    <Row>
      <TagsInput
        label="Allowed hosts"
        mono
        defaultValue={["api.stripe.com"]}
        placeholder="api.example.com"
        help="Requests to other hosts are refused."
        validate={(v) => (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) ? undefined : `"${v}" is not a host name.`)}
      />
      <TagsInput label="Scopes" mono defaultValue={["charges:read", "refunds:write"]} />
      <TagsInput label="Reviewers" required error="Add at least one reviewer." />
      <TagsInput label="Regions" defaultValue={["eu-west-1"]} disabled />
    </Row>,
  ],
  select: [
    "A list of choices that opens under its well.",
    <Select defaultValue="90">
      <SelectTrigger className="w-56" aria-label="Rotate every">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="30">Every 30 days</SelectItem>
        <SelectItem value="90">Every 90 days</SelectItem>
        <SelectItem value="never">Never</SelectItem>
      </SelectContent>
    </Select>,
  ],
  combobox: [
    "A select you can type in. The list narrows as you type; arrows and Enter pick.",
    <Combobox items={PROJECTS}>
      <ComboboxInput className="w-64" placeholder="Pick a project" aria-label="Project" />
      <ComboboxContent>
        <ComboboxEmpty>No project matches.</ComboboxEmpty>
        <ComboboxList>
          {(item: string) => (
            <ComboboxItem key={item} value={item}>
              {item}
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>,
  ],
  checkbox: [
    "A small well; a set one fills with the brand.",
    <Col>
      <Label>
        <Checkbox defaultChecked /> Notify me before a key expires
      </Label>
      <Label>
        <Checkbox /> Allow agents to request new scopes
      </Label>
      <Label>
        <Checkbox disabled /> Managed by your organisation
      </Label>
    </Col>,
  ],
  "radio-group": [
    "One choice from a short list you can read at once.",
    <RadioGroup defaultValue="30" aria-label="Rotate every">
      {["30", "90", "never"].map((v) => (
        <Label key={v}>
          <RadioGroupItem value={v} /> {v === "never" ? "Never" : `${v} days`}
        </Label>
      ))}
    </RadioGroup>,
  ],
  switch: [
    "A deadbolt. On, the bolt is thrown and the track turns teal. The bolt carries the keyhole; add data-plain to leave it off.",
    <Col>
      <Label>
        <Switch defaultChecked /> Require approval for write tools
      </Label>
      <Label>
        <Switch /> Pause every agent
      </Label>
      <Label>
        <Switch data-plain defaultChecked /> Email me a weekly summary
      </Label>
      <Label>
        <Switch data-plain /> Show archived projects
      </Label>
    </Col>,
  ],
  toggle: ["One thing that is on or off, as a button.", <ToggleDemo />],
  "relay-path": [
    "The product in one picture: the agent asks, Locksmith adds the key inside the vault, and only the answer comes back. Made for the landing page.",
    <RelayPath />,
  ],
  combination: [
    "A number on the wheels of a combination lock. When it changes, each wheel rolls to its digit. For one-time codes, countdowns and live counts.",
    <CombinationDemo />,
  ],
  "hold-to-confirm": [
    "For what cannot be undone. A click does nothing; hold it and the bolt travels across. Let go early and it springs back.",
    <HoldDemo />,
  ],
  "slide-to-unlock": [
    "A deadbolt you throw by hand. Drag the bolt to the end of the track, or focus it and press the right arrow four times; the left arrow draws it back.",
    <SlideDemo />,
  ],
  "lease-timer": [
    "How long a short-lived credential has left. The dial ring drains clockwise, amber in the last third and red in the last sixth.",
    <LeaseDemo />,
  ],
  "toggle-group": [
    "A row of tumbler pins: exactly one stands up.",
    <ToggleGroup type="single" defaultValue="all" aria-label="Show">
      <ToggleGroupItem value="all">All</ToggleGroupItem>
      <ToggleGroupItem value="agents">Used by agents</ToggleGroupItem>
      <ToggleGroupItem value="due">Rotation due</ToggleGroupItem>
    </ToggleGroup>,
  ],
  "date-picker": [
    "Dates here are lifetimes: when a grant expires, when a key rotates. The calendar draws that life as a run of days from today, and says how long it is.",
    <Row>
      <DatePicker
        label="Grant expires"
        presets={[7, 30, 90, 365]}
        help="The agent loses access at the end of this day."
      />
      <DatePicker label="Rotate on" required error="Pick a date." />
      <DatePicker label="Created" defaultValue="2026-11-02" disabled />
    </Row>,
  ],
  "date-range-picker": [
    "A window of days, for an audit log or a usage chart. Click the first day, then the last.",
    <Row>
      <DateRangePicker
        label="Audit window"
        presets={[7, 30, 90]}
        max={new Date().toISOString().slice(0, 10)}
        help="Logs are kept for 90 days."
      />
      <DateRangePicker label="Billing period" defaultValue={{ from: "2026-11-01", to: "2026-11-30" }} disabled />
    </Row>,
  ],
  calendar: [
    "A month of days to pick from. Build your own picker on it, or use DatePicker for lifetimes.",
    <CalendarDemo />,
  ],
  "file-upload": [
    "An empty slot waiting for a file. Click it, or drop a file on it.",
    <div style={{ maxWidth: 440 }}>
      <FileUpload
        label="Import .env"
        hint="Drop the file here, or choose one. Values are sealed on upload."
        accept=".env,text/plain"
        maxSize={64 * 1024}
      />
    </div>,
  ],
  table: [
    "A key register on a plate.",
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Agent</TableHead>
          <TableHead>Scope</TableHead>
          <TableHead className="text-right">Calls</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {AGENTS.slice(0, 3).map((a) => (
          <TableRow key={a.id}>
            <TableCell className="font-medium">{a.agent}</TableCell>
            <TableCell>
              <ScopeChip>charges:read</ScopeChip>
            </TableCell>
            <TableCell className="text-right font-mono">{a.calls}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>,
  ],
  chart: [
    "Charts for a usage dashboard, on Recharts through shadcn's Chart. The grid, ticks, tooltip and series colours come from the theme, so they follow light and dark.",
    <ChartsDemo />,
  ],
  "data-table": [
    "The Table for long lists: sort from the header, select rows, and keep the header in view. Use the controls to switch it between data, loading and empty. Shown here with FilterBar, ActionBar and ConfirmDialog.",
    <ListDemo />,
  ],
  "filter-bar": [
    "One row above a list: a search, then a button per filter that counts its picks.",
    <FilterBar
      defaultValue={{ state: ["Live"] }}
      filters={[
        { key: "env", label: "Environment", options: ["production", "staging", "development"] },
        { key: "state", label: "State", options: ["Live", "Paused", "Revoked"] },
        { key: "by", label: "Changed by", options: ["People", "Agents"] },
      ]}
    >
      <Input className="w-60" aria-label="Filter secrets" placeholder="Filter by key" />
    </FilterBar>,
  ],
  "action-bar": [
    "Appears with a selection: how many, what can be done to all of them, and a way out.",
    <ActionBarDemo />,
  ],
  facts: [
    "What is known about one thing, as label and value.",
    <Facts
      items={[
        { label: "Created", value: "12 March, by dana" },
        { label: "Version", value: <span className="font-mono">v4</span> },
        { label: "Sealed with", value: <CopyableId value="kms_01JD8Q9X4M7T2K5N" label="key id" /> },
      ]}
    />,
  ],
  stat: [
    "One count as an instrument readout: a lamp, the number in mono, and optionally how it moved and its recent history. Amber or red when it needs someone.",
    <Row>
      <Stat label="Secrets" value="48" note="in 6 projects" />
      <Stat
        label="Relays today"
        value="1,284"
        trend={{ value: "12%", direction: "up", good: true }}
        spark={[40, 52, 47, 61, 58, 72, 69, 84, 80, 96]}
      />
      <Stat label="Active agents" value="12" tone="live" note="3 signed in today" />
      <Stat label="Median relay" value="38" unit="ms" trend={{ value: "4ms", direction: "down", good: true }} />
      <Stat label="Rotation due" value="5" tone="warning" note="within 7 days" spark={[1, 1, 2, 2, 3, 3, 4, 5]} />
      <Stat label="Refused today" value="2" tone="danger" trend={{ value: "2", direction: "up", good: false }} />
    </Row>,
  ],
  meter: [
    "Usage against a limit, in ten notches. Amber from 80%, red at the limit.",
    <Col>
      <Meter label="Secrets" value={8} max={50} />
      <Meter label="Agent sessions today" value={430} max={500} />
      <Meter label="Storage" value={5} max={5} unit=" GB" />
    </Col>,
  ],
  timeline: [
    "What happened, newest first, on a rail of lamps. Violet means an agent did it.",
    <div style={{ maxWidth: 520 }}>
      <Timeline
        items={[
          {
            title: "Grant refused",
            when: "2 min ago",
            tone: "danger",
            children: "billing-sync asked for refunds:write.",
          },
          { title: "Key rotated", when: "3 hours ago", by: "agent", tone: "live" },
          {
            title: "Rotation due",
            when: "Yesterday",
            tone: "warning",
            children: "STRIPE_SECRET_KEY rotates in 12 days.",
          },
          { title: "Secret created", when: "12 March", children: "by dana" },
        ]}
      />
    </div>,
  ],
  "code-block": [
    "A command or snippet in a well, with one click to copy. Give it a language and the code is syntax-coloured.",
    <Col>
      <div className="w-full max-w-xl">{code(CMD)}</div>
      <div className="w-full max-w-xl">{code(SNIPPET_TSX, "tsx")}</div>
      <div className="w-full max-w-xl">{code(SNIPPET_JSON, "json")}</div>
    </Col>,
  ],
  avatar: [
    "People are round. Agents are square and violet.",
    <Row>
      <Avatar>
        <AvatarFallback>D</AvatarFallback>
      </Avatar>
      <Avatar>
        <AvatarFallback>N</AvatarFallback>
      </Avatar>
      <Avatar data-agent>
        <AvatarFallback>
          <Bot className="size-4" />
        </AvatarFallback>
      </Avatar>
      <Muted>dana, noor, deploy-bot</Muted>
    </Row>,
  ],
  kbd: [
    "A keycap.",
    <Row>
      <span>Search</span>
      <KbdGroup>
        <Kbd>⌘</Kbd>
        <Kbd>K</Kbd>
      </KbdGroup>
      <Muted>or</Muted>
      <Kbd>/</Kbd>
    </Row>,
  ],
  "copyable-id": [
    "An id in a well, ready to copy. Its type prefix sits in front as a small tag.",
    <CopyableId value="agt_01JD8Q9X4M7T2K5N8B3V6C0Z1Y" label="agent id" />,
  ],
  "copy-button": [
    "The kit's copy control on its own: it ticks for a moment after copying.",
    <Row>
      <span className="font-mono text-xs">smith login</span>
      <CopyButton value="smith login" label="command" />
    </Row>,
  ],
  secret: [
    "A value that stays sealed until you unlock it. Its length is never shown.",
    <Secret value="example-secret-value-51NqT8xKf2" />,
  ],
  badge: [
    "A key tag on a person or an action. Violet means an agent did it. Use it for a label that is a fact, not a state: for a state use Pill, for a permission ScopeChip, for a value someone picked Chip.",
    <Row>
      <Badge>charges:read</Badge>
      <Badge variant="secondary">Owner</Badge>
      <Badge variant="destructive">Revoked</Badge>
      <Badge data-by="agent">by agent</Badge>
    </Row>,
  ],
  chip: [
    "One picked value. The small cross removes it. Only for what a person chose and can take back; a label nobody chose is a Badge.",
    <Row>
      <Chip>production</Chip>
      <Chip onRemove={() => {}}>charges:read</Chip>
      <Chip onRemove={() => {}}>refunds:read</Chip>
    </Row>,
  ],
  pill: [
    "An indicator lamp: live, due, revoked, idle. Only for a state that can change; a fixed label is a Badge.",
    <Row>
      <Pill tone="live">Gateway live</Pill>
      <Pill tone="warning">Rotation due</Pill>
      <Pill tone="danger">Revoked</Pill>
      <Pill>Idle</Pill>
    </Row>,
  ],
  "scope-chip": [
    "A key tag for one permission an agent holds. Only for scopes; any other tag is a Badge.",
    <Row>
      <ScopeChip>repo:read</ScopeChip>
      <ScopeChip>issues:write</ScopeChip>
      <ScopeChip icon={<Users />}>org:members</ScopeChip>
    </Row>,
  ],
  "live-dot": [
    "Connected, with a slow pulse.",
    <Row>
      <LiveDot label="Connected" />
      <span>Daemon connected</span>
      <LiveDot pulse={false} label="Connected" />
      <Muted>no pulse</Muted>
    </Row>,
  ],
  loader: [
    "The vault dial turning and throwing its bolts, for a page or a panel that has nothing to show yet. One line or a button uses Spinner; a known amount of work uses Progress; content whose shape is known uses Skeleton.",
    <Row>
      <div className="loader-box">
        <Loader />
      </div>
      <div className="loader-box">
        <Loader>Opening the vault</Loader>
      </div>
      <div className="loader-box">
        <Loader done>Unlocked</Loader>
      </div>
    </Row>,
  ],
  spinner: [
    "The dial ring, for one line of text or a button that is still working. In a button, disable it and set aria-busy. Three variants of the same dial, each in three sizes.",
    <Col>
      <Row>
        <Spinner />
        <Muted>Checking the grant</Muted>
        <Button disabled aria-busy>
          <Spinner /> Rotating
        </Button>
      </Row>
      <div className="demo-variants">
        <span>Dial</span>
        <Row>
          <Spinner size="sm" />
          <Spinner />
          <Spinner size="lg" />
        </Row>
        <span>Ring</span>
        <Row>
          <Spinner variant="ring" size="sm" />
          <Spinner variant="ring" />
          <Spinner variant="ring" size="lg" />
        </Row>
        <span>Bolts</span>
        <Row>
          <Spinner variant="bolts" />
          <Spinner variant="bolts" size="lg" />
          <Spinner variant="bolts" className="size-9 text-(--brand)" />
        </Row>
      </div>
    </Col>,
  ],
  tumblers: [
    "Five pins rising to the shear line: a wait that is about access, such as a grant being checked or a vault unlocking. Any other wait uses Loader or Spinner.",
    <Row>
      <Tumblers label="Signing in" />
      <Muted>Signing in</Muted>
    </Row>,
  ],
  progress: [
    "A bolt in a track, thrown as far as the work has got. With no value, the bolt keeps throwing.",
    <ProgressDemo />,
  ],
  skeleton: [
    "Masked blocks in the shape of what is loading, with a slow sweep.",
    <Row>
      <Skeleton className="size-8 rounded-full" />
      <Col>
        <Skeleton className="h-3 w-56" />
        <Skeleton className="h-3 w-36" />
      </Col>
    </Row>,
  ],
  alert: [
    "Stays on the page until its cause is fixed. A toast is for what just happened.",
    <Col>
      <Alert>
        <Lock />
        <AlertTitle>Sealed with your own KMS key.</AlertTitle>
        <AlertDescription>Locksmith cannot read these values without it.</AlertDescription>
      </Alert>
      <Alert variant="destructive">
        <ShieldAlert />
        <AlertTitle>The gateway cannot reach your KMS.</AlertTitle>
        <AlertDescription>Agents are refused until it is back.</AlertDescription>
      </Alert>
    </Col>,
  ],
  sonner: [
    "A toast: confirms what just happened, then leaves. Five kinds each have a colour and an icon; any toast can take its own icon and a tone class.",
    <Row>
      <Button
        variant="outline"
        onClick={() => toast("Key rotated", { description: "Agents picked up the new value." })}
      >
        Plain
      </Button>
      <Button
        variant="outline"
        onClick={() =>
          toast.success("Grant approved", { description: "deploy-bot can read stripe/charges for 1 hour." })
        }
      >
        Success
      </Button>
      <Button
        variant="outline"
        onClick={() => toast.info("Rotation is due in 3 days", { description: "STRIPE_KEY, production." })}
      >
        Info
      </Button>
      <Button
        variant="outline"
        onClick={() =>
          toast.warning("This key is used by 4 agents", { description: "Revoking it stops them at once." })
        }
      >
        Warning
      </Button>
      <Button
        variant="outline"
        onClick={() => toast.error("Could not reach the gateway", { description: "Nothing was changed. Try again." })}
      >
        Error
      </Button>
      <Button
        variant="outline"
        onClick={() =>
          toast.promise(new Promise((done) => setTimeout(done, 1800)), {
            loading: "Rotating the key",
            success: "Key rotated",
            error: "Rotation failed",
          })
        }
      >
        Loading, then done
      </Button>
      <Button
        variant="outline"
        onClick={() =>
          toast("Secret deleted", {
            description: "DATABASE_URL, staging.",
            action: { label: "Undo", onClick: () => toast.success("Secret restored") },
            cancel: { label: "Dismiss", onClick: () => {} },
          })
        }
      >
        With actions
      </Button>
      <Button
        variant="outline"
        onClick={() =>
          toast("deploy-bot used stripe/charges", {
            description: "Through the relay. It never held the key.",
            icon: <Bot />,
            className: "toast-agent",
          })
        }
      >
        Agent, own icon
      </Button>
      <Button
        variant="outline"
        onClick={() =>
          toast("Vault unsealed", {
            description: "Locks again in 15 minutes.",
            icon: <KeyRound />,
            className: "toast-brand",
          })
        }
      >
        Brand, own icon
      </Button>
    </Row>,
  ],
  empty: [
    "An empty slot says what to do next. This is the bare part, for a layout of your own; the four usual cases are ready-made in EmptyState.",
    <Empty>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Bot />
        </EmptyMedia>
        <EmptyTitle>No agents yet</EmptyTitle>
        <EmptyDescription>Register one, then give it a grant.</EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button>Register an agent</Button>
      </EmptyContent>
    </Empty>,
  ],
  "empty-state": [
    "The four reasons a slot is empty, each with its own picture of the mark and one next step. Compact fits a table or a card. Start here; drop to Empty only when none of the four fits.",
    <Col>
      <Row>
        <EmptyState title="No agents yet" action={<Button>Register an agent</Button>}>
          Register one, then give it a grant.
        </EmptyState>
        <EmptyState
          kind="no-results"
          title="No secrets match"
          action={<Button variant="outline">Clear filters</Button>}
        >
          Nothing has the tag "payments" in this project.
        </EmptyState>
      </Row>
      <Row>
        <EmptyState
          kind="no-access"
          title="You can't see these keys"
          action={<Button variant="outline">Request access</Button>}
        >
          Only project owners can open the key register.
        </EmptyState>
        <EmptyState
          kind="error"
          title="The audit log didn't load"
          action={<Button variant="outline">Try again</Button>}
        >
          The gateway did not answer in time.
        </EmptyState>
      </Row>
      <EmptyState size="compact" kind="no-results" title="No grants match">
        Try a wider date range.
      </EmptyState>
    </Col>,
  ],
  dialog: [
    "A plate over a dimmed page, for a short form or a detail. Escape closes it.",
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline">Add a secret</Button>
      </DialogTrigger>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Add a secret</DialogTitle>
          <DialogDescription>It is sealed as soon as you save.</DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor="d-key">Key</FieldLabel>
          <Input id="d-key" className="font-mono" placeholder="STRIPE_SECRET_KEY" />
        </Field>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <DialogClose asChild>
            <Button>Save</Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>,
  ],
  "alert-dialog": [
    "Asks before an action that is hard to undo. It cannot be dismissed by clicking outside.",
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="destructive">Revoke grant</Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke deploy-bot's grant?</AlertDialogTitle>
          <AlertDialogDescription>
            It loses access at once. You can grant it again, but running sessions end.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive">Revoke</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>,
  ],
  "confirm-dialog": [
    "AlertDialog with one addition: for the worst actions, the person types the name first.",
    <ConfirmDemo />,
  ],
  sheet: [
    "Detail beside the list, without leaving it.",
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="outline">Open deploy-bot</Button>
      </SheetTrigger>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>deploy-bot</SheetTitle>
          <SheetDescription>Signed in 2 minutes ago from production.</SheetDescription>
        </SheetHeader>
        <div className="px-4">
          <Facts
            items={[
              { label: "Grants", value: "3" },
              { label: "Calls today", value: "1,204" },
            ]}
          />
        </div>
      </SheetContent>
    </Sheet>,
  ],
  popover: [
    "A floating plate on a button, for content that is more than a list of actions. It flips to stay on screen.",
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline">
          Rotation <ChevronsUpDown />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="flex w-72 flex-col gap-3">
        <b>Rotate every 30 days</b>
        <Muted>Next rotation in 12 days. Agents keep working while the value changes.</Muted>
        <Label>
          <Switch defaultChecked /> Rotate automatically
        </Label>
      </PopoverContent>
    </Popover>,
  ],
  "dropdown-menu": [
    "More actions on one thing, with icons and shortcuts. Arrow keys move through it.",
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline">
          Actions <ChevronsUpDown />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-52">
        <DropdownMenuLabel>STRIPE_SECRET_KEY</DropdownMenuLabel>
        <DropdownMenuItem>
          <KeyRound /> Rotate now <DropdownMenuShortcut>R</DropdownMenuShortcut>
        </DropdownMenuItem>
        <DropdownMenuItem>
          <Copy /> Copy id <DropdownMenuShortcut>C</DropdownMenuShortcut>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive">
          <Trash2 /> Delete
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>,
  ],
  command: [
    "Every page and action behind one search. Arrows move, Enter runs. Put it in a CommandDialog for a ⌘K palette.",
    <Command className="max-w-md border">
      <CommandInput placeholder="Search or jump to" />
      <CommandList>
        <CommandEmpty>Nothing matches.</CommandEmpty>
        <CommandGroup heading="Go to">
          <CommandItem>
            <Lock /> Secrets
          </CommandItem>
          <CommandItem>
            <Bot /> Agents
          </CommandItem>
          <CommandItem>
            <Settings /> Settings
          </CommandItem>
        </CommandGroup>
        <CommandGroup heading="Actions">
          <CommandItem>
            <KeyRound /> Rotate a key <CommandShortcut>R</CommandShortcut>
          </CommandItem>
          <CommandItem>
            <Plus /> Add a secret <CommandShortcut>N</CommandShortcut>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </Command>,
  ],
  tooltip: [
    "Names an icon or explains a control. Hover, focus, and Escape to hide.",
    <Tooltip>
      <TooltipTrigger asChild>
        <Button size="icon" variant="outline" aria-label="Rotate">
          <KeyRound />
        </Button>
      </TooltipTrigger>
      <TooltipContent>Rotate this key now</TooltipContent>
    </Tooltip>,
  ],
  sidebar: [
    "The pages of the console. The current page is a raised plate.",
    <div className="h-64 w-60 overflow-hidden rounded-lg border">
      <SidebarProvider className="min-h-0 h-full">
        <Sidebar collapsible="none" className="w-full">
          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupLabel>payments</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {(
                    [
                      ["Secrets", Lock, 8],
                      ["Agents", Bot, 3],
                      ["Grants", KeyRound, 15],
                    ] as const
                  ).map(([name, Icon, n], i) => (
                    <SidebarMenuItem key={name}>
                      <SidebarMenuButton isActive={i === 0}>
                        <Icon /> {name}
                      </SidebarMenuButton>
                      <SidebarMenuBadge>{n}</SidebarMenuBadge>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
        </Sidebar>
      </SidebarProvider>
    </div>,
  ],
  tabs: [
    "A line of names. The selected one carries the brand bar and its key tooth.",
    <Tabs defaultValue="grants">
      <TabsList variant="line">
        <TabsTrigger value="grants">Grants</TabsTrigger>
        <TabsTrigger value="sessions">Sessions</TabsTrigger>
        <TabsTrigger value="activity">Activity</TabsTrigger>
      </TabsList>
      <TabsContent value="grants">
        <Muted>Three agents hold a grant.</Muted>
      </TabsContent>
      <TabsContent value="sessions">
        <Muted>One session is open.</Muted>
      </TabsContent>
      <TabsContent value="activity">
        <Muted>Nothing in the last hour.</Muted>
      </TabsContent>
    </Tabs>,
  ],
  breadcrumb: [
    "Where this thing lives. The current item is set in mono, like the key itself.",
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink href="#/breadcrumb">Secrets</BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbLink href="#/breadcrumb">payments</BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          <BreadcrumbPage>STRIPE_SECRET_KEY</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>,
  ],
  pagination: [
    "Pages of a long list.",
    <Pagination>
      <PaginationContent>
        <PaginationItem>
          <PaginationPrevious href="#/pagination" />
        </PaginationItem>
        {[1, 2, 3].map((n) => (
          <PaginationItem key={n}>
            <PaginationLink href="#/pagination" isActive={n === 2}>
              {n}
            </PaginationLink>
          </PaginationItem>
        ))}
        <PaginationItem>
          <PaginationEllipsis />
        </PaginationItem>
        <PaginationItem>
          <PaginationNext href="#/pagination" />
        </PaginationItem>
      </PaginationContent>
    </Pagination>,
  ],
  stepper: ["A short, ordered job. Each step is a pin: set, current, or waiting.", <StepperDemo />],
  "plan-badge": [
    "A lock and a plan's name, on something the current plan does not include: a navigation item, a tab, a setting row. Show it only where the feature is missing; a feature the plan has carries no badge.",
    <Row>
      <span className="inline-flex items-center gap-2">
        Rotation <PlanBadge plan="Team" />
      </span>
      <span className="inline-flex items-center gap-2">
        Audit streaming <PlanBadge plan="Enterprise" />
      </span>
    </Row>,
  ],
  "upgrade-notice": [
    "Stands where a page or a section would be when the plan does not include it. It says what the feature does and which plan has it, with one next step. Never hide a paid feature: show this instead. Unlock, export, read and write are never behind it.",
    <Col>
      <UpgradeNotice plan="Team" title="Secret rotation" action={<Button>See plans</Button>}>
        Replace a secret on a schedule, and everywhere it is used, without anyone handling the new value.
      </UpgradeNotice>
      <UpgradeNotice
        size="compact"
        plan="Enterprise"
        title="Audit streaming"
        action={<Button variant="outline">Talk to us</Button>}
      >
        Send every audit event to your own SIEM as it happens.
      </UpgradeNotice>
    </Col>,
  ],
  labels: [
    "The kit says a few words of its own: button names for screen readers and a handful of visible defaults. They are English. An app in another language wraps its root in LabelsProvider and passes the ones it translates.",
    <LabelsProvider
      labels={{ copy: (what) => `Copiar ${what}`, copied: "Copiado", remove: (what) => `Quitar ${what}` }}
    >
      <Row>
        <CopyableId value="agt_01JD8Q9X4M7T2K5N8B3V6C0Z1Y" />
        <Chip onRemove={() => {}}>api.stripe.com</Chip>
      </Row>
    </LabelsProvider>,
  ],
  link: [
    "Text that goes somewhere. An arrow marks links that leave the product.",
    <Row>
      <span>
        Read how <Link href="#/secret">values are sealed</Link> before you add one.
      </span>
      <Link href="https://example.com/rotation" external>
        Rotation guide
      </Link>
    </Row>,
  ],
  "page-header": [
    "One per screen: what this is, how many, and the main actions.",
    <PageHeader
      title="Secrets"
      lede="8 secrets in payments / production. Values are sealed; only the gateway can unwrap them."
    >
      <Button variant="outline">Import</Button>
      <Button>Add a secret</Button>
    </PageHeader>,
  ],
  card: [
    "A flat plate for one topic.",
    <Card className="max-w-sm">
      <CardHeader>
        <CardTitle>Get started</CardTitle>
        <CardDescription>Create a project, add a secret, then register an agent and give it a grant.</CardDescription>
      </CardHeader>
      <CardContent>
        <Meter label="Setup" value={2} max={4} />
      </CardContent>
      <CardFooter>
        <Button>Continue</Button>
      </CardFooter>
    </Card>,
  ],
  accordion: [
    "Sections that open in place, for detail most people skip.",
    <Accordion type="single" collapsible defaultValue="a" className="max-w-xl">
      <AccordionItem value="a">
        <AccordionTrigger>How are values sealed?</AccordionTrigger>
        <AccordionContent>Each value is encrypted with a key that never leaves your KMS.</AccordionContent>
      </AccordionItem>
      <AccordionItem value="b">
        <AccordionTrigger>Can an agent read a secret?</AccordionTrigger>
        <AccordionContent>No. The gateway uses the value on the agent's behalf and never returns it.</AccordionContent>
      </AccordionItem>
    </Accordion>,
  ],
  collapsible: [
    "One region that shows and hides.",
    <Collapsible className="flex max-w-sm flex-col gap-2">
      <CollapsibleTrigger asChild>
        <Button variant="outline" size="sm">
          Advanced <ChevronsUpDown />
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <Muted>Requests are signed with a short-lived token, minted per call.</Muted>
      </CollapsibleContent>
    </Collapsible>,
  ],
  separator: [
    "A rule between two things that are not the same topic.",
    <div className="max-w-sm">
      <span>Sign in with your work account.</span>
      <Separator className="my-3" />
      <Muted>Need help? Ask your workspace owner.</Muted>
    </div>,
  ],
  "setting-row": [
    "One setting: what it does on the left, its control on the right.",
    <Card className="max-w-xl px-5">
      <SettingRow
        title="Require approval for write tools"
        about="An agent waits for a person before it changes anything."
      >
        <Switch defaultChecked aria-label="Require approval for write tools" />
      </SettingRow>
      <SettingRow title="Session length" about="How long an agent stays signed in.">
        <Select defaultValue="8">
          <SelectTrigger aria-label="Session length">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1">1 hour</SelectItem>
            <SelectItem value="8">8 hours</SelectItem>
          </SelectContent>
        </Select>
      </SettingRow>
    </Card>,
  ],
};

export { code };
