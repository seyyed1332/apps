(() => {
  const body = document.body;
  const toggle = document.getElementById("menuToggle");

  if (toggle) {
    toggle.addEventListener("click", () => {
      const isOpen = body.getAttribute("data-menu-open") === "true";
      body.setAttribute("data-menu-open", isOpen ? "false" : "true");
    });
  }
})();
