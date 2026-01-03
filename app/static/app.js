(() => {
  const body = document.body;
  const toggle = document.getElementById("menuToggle");
  const panel = document.getElementById("menuPanel");

  const setOpen = (isOpen) => {
    body.setAttribute("data-menu-open", isOpen ? "true" : "false");
    if (toggle) {
      toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    }
    if (panel) {
      panel.setAttribute("aria-hidden", isOpen ? "false" : "true");
    }
  };

  if (toggle && panel) {
    toggle.addEventListener("click", (event) => {
      event.stopPropagation();
      const isOpen = body.getAttribute("data-menu-open") === "true";
      setOpen(!isOpen);
    });

    document.addEventListener("click", (event) => {
      const isOpen = body.getAttribute("data-menu-open") === "true";
      if (!isOpen) return;
      if (!panel.contains(event.target) && !toggle.contains(event.target)) {
        setOpen(false);
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    });
  }

  const tabs = document.querySelectorAll("[data-group-tab]");
  const panels = document.querySelectorAll("[data-group-panel]");
  if (tabs.length && panels.length) {
    const activate = (name) => {
      tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.groupTab === name);
      });
      panels.forEach((panel) => {
        panel.classList.toggle("hidden", panel.dataset.groupPanel !== name);
      });
    };

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        activate(tab.dataset.groupTab);
      });
    });
  }

  const inboundRows = document.querySelectorAll(".inbound-row-wrap");
  inboundRows.forEach((wrapper) => {
    const input = wrapper.querySelector("input[type='checkbox']");
    const row = wrapper.querySelector(".inbound-row");
    if (!input || !row) return;

    const syncState = () => {
      wrapper.classList.toggle("active", input.checked);
    };

    row.addEventListener("click", (event) => {
      if (event.target.closest("label")) return;
      if (event.target.closest("button")) return;
      input.checked = !input.checked;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });

    input.addEventListener("change", syncState);
    syncState();
  });

  const detailToggles = document.querySelectorAll("[data-details-target]");
  detailToggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
      const targetId = toggle.getAttribute("data-details-target");
      if (!targetId) return;
      const target = document.getElementById(targetId);
      if (!target) return;
      const isHidden = target.hasAttribute("hidden");
      if (isHidden) {
        target.removeAttribute("hidden");
        toggle.textContent = "Hide details";
      } else {
        target.setAttribute("hidden", "");
        toggle.textContent = "Details";
      }
    });
  });
})();
