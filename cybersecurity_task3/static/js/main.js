// Basic UI helpers (can be extended later)
document.addEventListener("DOMContentLoaded", () => {
  // Example: auto-dismiss flashes after 4s
  const flashes = document.querySelectorAll(".flash");
  flashes.forEach(f => {
    setTimeout(() => {
      f.style.opacity = "0";
      setTimeout(() => f.remove(), 400);
    }, 4000);
  });
});