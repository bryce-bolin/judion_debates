/* global document, MutationObserver */

// Minimal enhancer: delegate to base.html's window.enhanceCodeBlocks
(function () {
  function enhance(root) {
    if (typeof window.enhanceCodeBlocks === "function") {
      window.enhanceCodeBlocks(root || document);
    }
  }

  // Initial pass
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => enhance(document));
  } else {
    enhance(document);
  }

  // Watch for newly added messages/code and enhance them
  const target =
    document.getElementById("main") ||
    document.getElementById("messages") ||
    document.body;

  if (target && typeof MutationObserver !== "undefined") {
    const mo = new MutationObserver((mutations) => {
      mutations.forEach((m) => {
        m.addedNodes.forEach((n) => {
          if (n.nodeType === 1) enhance(n);
        });
      });
    });
    mo.observe(target, { childList: true, subtree: true });
  }
})();