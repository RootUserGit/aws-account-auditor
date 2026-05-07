"use client";

import ButtonDropdown, {
  type ButtonDropdownProps,
} from "@cloudscape-design/components/button-dropdown";

type Props = {
  items: ButtonDropdownProps.Item[];
  onClick?: (id: string) => void;
};

export function RowActionsDropdown({ items, onClick }: Readonly<Props>) {
  return (
    <div className="row-actions-dropdown flex items-center justify-center">
      <ButtonDropdown
        variant="icon"
        ariaLabel="Actions"
        expandToViewport
        items={items}
        onItemClick={({ detail }) => {
          if (detail.id) onClick?.(detail.id);
        }}
      />
    </div>
  );
}
