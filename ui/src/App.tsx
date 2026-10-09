import { createSignal, For } from "solid-js";

interface Section {
  id: string;
  label: string;
}

// UI strings will move to the localisation catalogue (sv, en).
const SECTIONS: readonly Section[] = [
  { id: "ipam", label: "IPAM" },
  { id: "dns", label: "DNS" },
  { id: "dhcp", label: "DHCP" },
  { id: "topology", label: "Topology" },
  { id: "jobs", label: "Jobs" },
  { id: "settings", label: "Settings" },
];

export default function App() {
  const [active, setActive] = createSignal<string>(SECTIONS[0].id);
  const activeLabel = () =>
    SECTIONS.find((section) => section.id === active())?.label ?? "";

  return (
    <div class="app">
      <header class="app-header">
        <span class="brand">DDI</span>
        <span class="subtitle">DNS · DHCP · IPAM</span>
      </header>
      <nav class="app-nav" aria-label="Main">
        <ul>
          <For each={SECTIONS}>
            {(section) => (
              <li>
                <button
                  type="button"
                  classList={{ active: active() === section.id }}
                  aria-current={active() === section.id ? "page" : undefined}
                  onClick={() => setActive(section.id)}
                >
                  {section.label}
                </button>
              </li>
            )}
          </For>
        </ul>
      </nav>
      <main class="app-main">
        <h1>{activeLabel()}</h1>
        <p>Pre-alpha: this section is not implemented yet.</p>
      </main>
    </div>
  );
}
