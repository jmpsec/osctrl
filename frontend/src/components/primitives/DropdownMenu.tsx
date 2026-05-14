/**
 * DropdownMenu — thin Radix wrapper with osctrl token styling.
 * Exposes the same sub-components as Radix so callers use the
 * familiar composable API: <DropdownMenu.Root>, <DropdownMenu.Trigger>, etc.
 */
import * as RadixDropdown from '@radix-ui/react-dropdown-menu';
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from 'react';
import { cn } from '$/lib/cn';

const Root = RadixDropdown.Root;
const Trigger = RadixDropdown.Trigger;
const Group = RadixDropdown.Group;
const Portal = RadixDropdown.Portal;
const Sub = RadixDropdown.Sub;
const RadioGroup = RadixDropdown.RadioGroup;

const Content = forwardRef<
  ElementRef<typeof RadixDropdown.Content>,
  ComponentPropsWithoutRef<typeof RadixDropdown.Content>
>(({ className, sideOffset = 6, ...props }, ref) => (
  <RadixDropdown.Portal>
    <RadixDropdown.Content
      ref={ref}
      sideOffset={sideOffset}
      className={cn(
        'z-50 min-w-[160px] overflow-hidden rounded-xl',
        'bg-[color:var(--bg-1)] border border-[color:var(--border)]',
        'shadow-[0_4px_12px_rgba(0,0,0,0.18)] p-1',
        'data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95',
        'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
        'data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2',
        'data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2',
        className
      )}
      {...props}
    />
  </RadixDropdown.Portal>
));
Content.displayName = RadixDropdown.Content.displayName;

const Item = forwardRef<
  ElementRef<typeof RadixDropdown.Item>,
  ComponentPropsWithoutRef<typeof RadixDropdown.Item> & { inset?: boolean }
>(({ className, inset, ...props }, ref) => (
  <RadixDropdown.Item
    ref={ref}
    className={cn(
      'relative flex cursor-pointer select-none items-center gap-2',
      'rounded-md px-2 py-1.5 text-sm text-[color:var(--text-2)]',
      'outline-none transition-colors duration-[120ms]',
      'hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)]',
      'focus:bg-[color:var(--bg-2)] focus:text-[color:var(--text-1)]',
      'data-[disabled]:pointer-events-none data-[disabled]:opacity-40',
      inset && 'pl-8',
      className
    )}
    {...props}
  />
));
Item.displayName = RadixDropdown.Item.displayName;

const Label = forwardRef<
  ElementRef<typeof RadixDropdown.Label>,
  ComponentPropsWithoutRef<typeof RadixDropdown.Label> & { inset?: boolean }
>(({ className, inset, ...props }, ref) => (
  <RadixDropdown.Label
    ref={ref}
    className={cn(
      'px-2 py-1 text-[10px] font-medium uppercase tracking-[0.12em] text-[color:var(--text-3)]',
      'font-mono-tabular',
      inset && 'pl-8',
      className
    )}
    {...props}
  />
));
Label.displayName = RadixDropdown.Label.displayName;

const Separator = forwardRef<
  ElementRef<typeof RadixDropdown.Separator>,
  ComponentPropsWithoutRef<typeof RadixDropdown.Separator>
>(({ className, ...props }, ref) => (
  <RadixDropdown.Separator
    ref={ref}
    className={cn('-mx-1 my-1 h-px bg-[color:var(--border)]', className)}
    {...props}
  />
));
Separator.displayName = RadixDropdown.Separator.displayName;

const RadioItem = forwardRef<
  ElementRef<typeof RadixDropdown.RadioItem>,
  ComponentPropsWithoutRef<typeof RadixDropdown.RadioItem>
>(({ className, children, ...props }, ref) => (
  <RadixDropdown.RadioItem
    ref={ref}
    className={cn(
      'relative flex cursor-pointer select-none items-center gap-2',
      'rounded-md px-2 py-1.5 text-sm text-[color:var(--text-2)]',
      'outline-none transition-colors duration-[120ms]',
      'hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)]',
      'focus:bg-[color:var(--bg-2)] focus:text-[color:var(--text-1)]',
      'data-[state=checked]:text-[color:var(--text-1)]',
      'data-[disabled]:pointer-events-none data-[disabled]:opacity-40',
      className
    )}
    {...props}
  >
    <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
      <RadixDropdown.ItemIndicator>
        <svg viewBox="0 0 8 8" className="h-2 w-2 fill-[color:var(--signal)]">
          <circle cx="4" cy="4" r="3" />
        </svg>
      </RadixDropdown.ItemIndicator>
    </span>
    <span className="pl-6">{children}</span>
  </RadixDropdown.RadioItem>
));
RadioItem.displayName = RadixDropdown.RadioItem.displayName;

export const DropdownMenu = {
  Root,
  Trigger,
  Content,
  Item,
  Label,
  Separator,
  Group,
  Portal,
  Sub,
  RadioGroup,
  RadioItem,
};
