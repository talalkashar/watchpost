"use strict";

// The sign-in form can paint before its submit handler loads.
document.addEventListener("submit", (event) => {
  if (event.target.id === "login-form" && !event.defaultPrevented) {
    event.preventDefault();
    event.target.dataset.pendingSubmit = "true";
  }
});
document.querySelector('#login-form button[type="submit"]').disabled = false;

// The deferred loader runs after the stylesheet. Fetch the console scripts in
// parallel from there, preserving their original execution order.
for (const source of document.getElementById("console-scripts").content.querySelectorAll("script")) {
  const script = document.createElement("script");
  script.async = false;
  script.src = source.getAttribute("src");
  document.head.append(script);
}
