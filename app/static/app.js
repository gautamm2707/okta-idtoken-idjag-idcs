"use strict";
for (const inspector of document.querySelectorAll("[data-inspector]")) {
  const tabs = Array.from(inspector.querySelectorAll('[role="tab"]'));
  const select = (tab) => {
    for (const item of tabs) {
      const active = item === tab;
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
      document.getElementById(item.getAttribute("aria-controls")).hidden = !active;
    }
  };
  for (const tab of tabs) {
    tab.addEventListener("click", () => select(tab));
    tab.addEventListener("keydown", (event) => {
      const enabled = tabs.filter(item => !item.disabled);
      const index = enabled.indexOf(tab);
      let next;
      if (event.key === "ArrowRight") next = enabled[(index + 1) % enabled.length];
      if (event.key === "ArrowLeft") next = enabled[(index + enabled.length - 1) % enabled.length];
      if (event.key === "Home") next = enabled[0];
      if (event.key === "End") next = enabled[enabled.length - 1];
      if (next) { event.preventDefault(); select(next); next.focus(); }
    });
  }
}
for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.closest(".tab-panel").querySelector("pre").textContent);
      button.textContent = "Copied";
    } catch { button.textContent = "Select text to copy"; }
  });
}
