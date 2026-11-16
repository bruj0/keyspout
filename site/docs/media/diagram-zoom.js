/**
 * Click-to-zoom for the Mermaid diagrams.
 *
 * # Why this exists
 *
 * Several of the diagrams are wider than the content column, and a reader on
 * a narrow screen has to scroll sideways to reach the right-hand end. A
 * diagram that describes a data flow or a sequence is naturally wide, and
 * narrowing it to fit would make it unreadable rather than tidy.
 *
 * So a wide diagram is *made* readable by letting the reader zoom into it,
 * rather than by shrinking it.
 *
 * # Why the shadow root is intercepted
 *
 * Material renders a Mermaid diagram into a **closed** shadow root:
 *
 *   const root = host.attachShadow({ mode: "closed" });
 *   root.innerHTML = svg;
 *
 * A closed shadow root is not reachable from the document. `host.shadowRoot`
 * is `null`, so the rendered SVG cannot be styled, measured, copied or moved
 * by a stylesheet or a query - the diagram is a sealed box.
 *
 * The seal is opened at the source: `attachShadow` is wrapped *before*
 * Material's asynchronous render runs, and the wrapper remembers the root it
 * created. The wrapper stays installed, because Material's render can happen
 * at any point in the page's life and there is no moment at which it is
 * safe to remove it.
 */
(function () {
  "use strict";

  // The width beyond which a diagram is offered the zoom. Below it the
  // diagram already fits and zooming would be noise.
  const WIDE = 900;

  /** The shadow roots Material created, by host element. */
  const roots = new WeakMap();

  /**
   * Remember the shadow root Material creates.
   *
   * This wrapper is installed at the top of the script, which runs before
   * the bundle's observer touches the page, so the render is always
   * intercepted.
   */
  const attachShadow = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (options) {
    const root = attachShadow.call(this, options);
    roots.set(this, root);
    return root;
  };

  const overlay = {
    element: null,
    svg: null,
    scale: 1,
    base: null,
  };

  function open(host) {
    const root = roots.get(host);
    if (!root) return;

    const source = root.querySelector("svg");
    if (!source) return;

    // Copy the SVG into the light DOM. The copy carries the viewBox, so
    // the zoom is a viewBox change and not a CSS transform: the text stays
    // sharp and the geometry stays exact.
    const copy = source.cloneNode(true);
    copy.removeAttribute("style");
    copy.setAttribute("width", "100%");
    copy.style.maxWidth = "none";
    copy.style.height = "auto";
    copy.style.display = "block";

    const panel = document.createElement("div");
    panel.className = "ksp-zoom__panel";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.setAttribute("aria-label", "The diagram, enlarged");

    const scroller = document.createElement("div");
    scroller.className = "ksp-zoom__scroller";
    scroller.appendChild(copy);

    const bar = document.createElement("div");
    bar.className = "ksp-zoom__bar";
    bar.innerHTML =
      '<button type="button" class="ksp-zoom__button" data-ksp-zoom="out" ' +
      'aria-label="Zoom out">&minus;</button>' +
      '<span class="ksp-zoom__level">100%</span>' +
      '<button type="button" class="ksp-zoom__button" data-ksp-zoom="in" ' +
      'aria-label="Zoom in">+</button>' +
      '<button type="button" class="ksp-zoom__close" data-ksp-zoom="close" ' +
      'aria-label="Close">&times;</button>';

    panel.appendChild(scroller);
    panel.appendChild(bar);
    document.body.appendChild(panel);
    document.body.classList.add("ksp-zoom--open");

    overlay.element = panel;
    overlay.svg = copy;
    overlay.scale = 1;

    const viewBox = copy.getAttribute("viewBox");
    overlay.base = viewBox ? viewBox.split(/\s+/).map(Number) : null;

    panel.addEventListener("click", onPanelClick);
    document.addEventListener("keydown", onKeyDown);

    apply();
  }

  function close() {
    if (!overlay.element) return;
    document.removeEventListener("keydown", onKeyDown);
    overlay.element.remove();
    overlay.element = null;
    overlay.svg = null;
    document.body.classList.remove("ksp-zoom--open");
  }

  function onPanelClick(event) {
    const action = event.target.getAttribute("data-ksp-zoom");
    if (action === "close") return close();
    if (action === "in") return zoom(1.25);
    if (action === "out") return zoom(0.8);
    if (event.target === overlay.element) return close();
  }

  function onKeyDown(event) {
    if (event.key === "Escape") {
      close();
      return;
    }
    if (event.key === "+" || event.key === "=") {
      zoom(1.25);
      return;
    }
    if (event.key === "-") {
      zoom(0.8);
    }
  }

  function zoom(factor) {
    const next = Math.min(8, Math.max(0.2, overlay.scale * factor));
    if (next === overlay.scale) return;
    overlay.scale = next;
    apply();
  }

  function apply() {
    if (!overlay.svg || !overlay.base) return;

    const width = overlay.base[2];
    const height = overlay.base[3];

    // The zoom is a viewBox change: the same drawing, seen through a
    // smaller window. The aspect ratio is preserved, so the diagram does
    // not distort.
    overlay.svg.setAttribute(
      "viewBox",
      [
        overlay.base[0],
        overlay.base[1],
        width / overlay.scale,
        height / overlay.scale,
      ].join(" ")
    );
    overlay.svg.style.width = `${overlay.scale * 100}%`;
    overlay.svg.style.height = "auto";

    const level = overlay.element.querySelector(".ksp-zoom__level");
    if (level) level.textContent = `${Math.round(overlay.scale * 100)}%`;
  }

  /**
   * Give every wide diagram a way in.
   *
   * The button is placed *next to* the diagram rather than over it, so it
   * never covers part of the drawing and never intercepts a click that was
   * meant for the diagram.
   */
  function decorate(host) {
    if (host.dataset.kspZoom === "done") return;

    const root = roots.get(host);
    if (!root) return;

    const source = root.querySelector("svg");
    if (!source) return;

    host.dataset.kspZoom = "done";

    // The intrinsic width is the viewBox's width: the coordinate system
    // the diagram was laid out in. The host's own width is the width the
    // container allowed, which is the *squeezed* width, and comparing
    // against it would say a diagram is narrow when it was only narrowed
    // by the column it happens to sit in.
    const viewBox = source.getAttribute("viewBox");
    const intrinsic = viewBox ? Number(viewBox.split(/\s+/)[2]) : 0;

    if (intrinsic < WIDE) return;

    const button = document.createElement("button");
    button.type = "button";
    button.className = "ksp-zoom__open";
    button.textContent = "Enlarge";
    button.setAttribute("aria-label", "Enlarge this diagram");
    button.addEventListener("click", () => open(host));

    host.parentNode.insertBefore(button, host);
  }

  function scan() {
    document.querySelectorAll(".mermaid").forEach(decorate);
  }

  function init() {
    scan();
    // Material renders a Mermaid diagram asynchronously, and replaces the
    // element it was given. The shadow root therefore appears after the
    // page's scripts have run, so the scan is repeated until every diagram
    // has one.
    let attempts = 0;
    const timer = setInterval(() => {
      scan();
      attempts += 1;
      if (attempts > 40) clearInterval(timer);
    }, 250);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // MkDocs Material's instant navigation replaces the page content
  // without a full reload, so the scan is repeated on every navigation.
  document.addEventListener("DOMContentSwitch", () => {
    document.querySelectorAll("[data-ksp-zoom]").forEach((element) => {
      delete element.dataset.kspZoom;
    });
    scan();
  });
})();
