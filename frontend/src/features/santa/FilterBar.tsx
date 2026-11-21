import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';

export interface FilterField {
  key: string;
  label: string;
  /** A select with these options; the first is usually "any" with an empty value. */
  options?: { value: string; label: string }[];
}

/** Filter inputs applied on submit; empty values are left out. */
export function FilterBar({ id, fields, onApply }: { id: string; fields: FilterField[]; onApply: (filter: Record<string, string>) => void }) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<Record<string, string>>({});

  function submit(e: FormEvent) {
    e.preventDefault();
    onApply(Object.fromEntries(Object.entries(draft).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v !== '')));
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2 border-b border-[color:var(--border)] p-3">
      {fields.map((f) => (
        <div key={f.key} className="min-w-[10rem] flex-1">
          <Label htmlFor={`${id}-${f.key}`}>{f.label}</Label>
          {f.options ? (
            <select
              id={`${id}-${f.key}`}
              className="h-8 w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
              value={draft[f.key] ?? ''}
              onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
            >
              {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          ) : (
            <Input id={`${id}-${f.key}`} value={draft[f.key] ?? ''} onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })} />
          )}
        </div>
      ))}
      <Button type="submit" size="sm">{t('commonExt.applyFilters')}</Button>
      <Button
        type="button"
        size="sm"
        variant="ghost"
        onClick={() => {
          setDraft({});
          onApply({});
        }}
      >
        {t('commonExt.clearFilters')}
      </Button>
    </form>
  );
}
