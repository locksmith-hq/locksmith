import { useId, useState } from "react";
import { Upload } from "lucide-react";
import { Chip } from "@locksmith-hq/chip";

export interface FileUploadProps {
  /** The bold text in the slot. */
  label: string;
  /**
   * Text after the label.
   * @default "Drop a file here, or choose one."
   */
  hint?: string;
  /** File types offered by the file dialog, as in the native `accept` attribute. Dropped files are not checked, so validate in `onFiles`. */
  accept?: string;
  /** Allows more than one file. */
  multiple?: boolean;
  /** Largest file allowed, in bytes. A larger file is refused with a message under the slot. */
  maxSize?: number;
  /** Error message under the slot, for a check the parent made. A refused file shows its own message first. */
  error?: string;
  /** Turns the slot off: it cannot be focused, clicked or dropped on. */
  disabled?: boolean;
  /** Called with the chosen files, and again each time one is removed. */
  onFiles?: (files: File[]) => void;
}

// 1536 -> "1.5 KB". Binary units, one decimal under 10.
export function fileSize(bytes: number): string {
  const units = ["bytes", "KB", "MB", "GB"];
  let n = bytes,
    i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n < 10 && i > 0 ? n.toFixed(1).replace(/\.0$/, "") : Math.round(n)} ${units[i]}`;
}

// An empty slot waiting for a file: click it, focus it and press Enter, or drop a file on it.
// shortcut: `accept` filters the file dialog only, a dropped file is not checked; validate in onFiles.
export function FileUpload(p: FileUploadProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [over, setOver] = useState(false);
  const [refused, setRefused] = useState<string>();
  const id = useId();
  const error = refused || p.error;
  const put = (f: File[]) => {
    setFiles(f);
    p.onFiles?.(f);
  };
  const take = (list: FileList | null) => {
    if (p.disabled) return;
    const all = Array.from(list || []).slice(0, p.multiple ? undefined : 1);
    const big = all.filter((x) => p.maxSize !== undefined && x.size > p.maxSize);
    const f = all.filter((x) => !big.includes(x));
    setRefused(big.length ? `${big.map((x) => x.name).join(", ")}: larger than ${fileSize(p.maxSize!)}.` : undefined);
    if (f.length) put(f);
  };
  return (
    <div data-slot="file-upload" className="upload-wrap" data-disabled={p.disabled || undefined}>
      <label
        className="upload"
        data-over={over || undefined}
        data-invalid={error ? true : undefined}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(!p.disabled);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          take(e.dataTransfer.files);
        }}
      >
        <input
          type="file"
          className="sr-only"
          accept={p.accept}
          multiple={p.multiple}
          disabled={p.disabled}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={error ? id + "-note" : undefined}
          onChange={(e) => {
            take(e.target.files);
            e.target.value = "";
          }}
        />
        <span className="state-ic">
          <Upload />
        </span>
        <span>
          <b>{p.label}</b> <span className="muted">{p.hint || "Drop a file here, or choose one."}</span>
        </span>
      </label>
      {error ? (
        <span id={id + "-note"} className="error" role="alert">
          {error}
        </span>
      ) : null}
      {files.length ? (
        <div className="upload-files">
          {files.map((f, i) => (
            <Chip key={i} onRemove={p.disabled ? undefined : () => put(files.filter((_, j) => j !== i))}>
              {f.name}
            </Chip>
          ))}
        </div>
      ) : null}
    </div>
  );
}
