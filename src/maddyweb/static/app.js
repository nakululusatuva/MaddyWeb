"use strict";

(() => {
  const form = document.querySelector("#compose-form");
  const editor = document.querySelector("#rich-editor");
  const source = document.querySelector("#html-source");
  const imageInput = document.querySelector("#inline-images");
  const cidFields = document.querySelector("#inline-cids");

  const hasEditor = form && editor && source && imageInput && cidFields;
  let previewUrls = [];

  if (hasEditor) document.querySelectorAll("[data-editor-command]").forEach((button) => {
    button.addEventListener("click", () => {
      const command = button.getAttribute("data-editor-command");
      if (command) document.execCommand(command, false);
      editor.focus();
    });
  });

  if (hasEditor) imageInput.addEventListener("change", () => {
    previewUrls.forEach((url) => URL.revokeObjectURL(url));
    previewUrls = [];
    cidFields.replaceChildren();
    editor.querySelectorAll("img[data-generated-cid]").forEach((node) => node.remove());

    Array.from(imageInput.files || []).forEach((file) => {
      const cid = `${crypto.randomUUID()}@maddyweb.local`;
      const hidden = document.createElement("input");
      hidden.type = "hidden";
      hidden.name = "inline_cids";
      hidden.value = cid;
      cidFields.append(hidden);

      const image = document.createElement("img");
      image.alt = file.name;
      image.dataset.generatedCid = cid;
      const previewUrl = URL.createObjectURL(file);
      previewUrls.push(previewUrl);
      image.src = previewUrl;
      editor.append(image);
    });
  });

  window.addEventListener("beforeunload", () => {
    previewUrls.forEach((url) => URL.revokeObjectURL(url));
  });

  const syncEditor = () => {
    if (!hasEditor) return;
    const clone = editor.cloneNode(true);
    clone.querySelectorAll("img[data-generated-cid]").forEach((image) => {
      image.setAttribute("src", `cid:${image.getAttribute("data-generated-cid")}`);
      image.removeAttribute("data-generated-cid");
    });
    source.value = clone.innerHTML.trim();
  };

  document.querySelectorAll('form[enctype="multipart/form-data"]').forEach((uploadForm) => {
    uploadForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      syncEditor();
      const token = uploadForm.querySelector('input[name="_csrf"]');
      if (!(token instanceof HTMLInputElement)) return;
      const response = await fetch(uploadForm.action, {
        method: "POST",
        body: new FormData(uploadForm),
        credentials: "same-origin",
        redirect: "follow",
        headers: {"X-CSRF-Token": token.value},
      });
      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }
      const page = await response.text();
      document.open();
      document.write(page);
      document.close();
    });
  });
})();
