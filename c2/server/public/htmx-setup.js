document.addEventListener('DOMContentLoaded', () => {
  document.body.addEventListener('htmx:beforeSwap', (evt) => {
    if (evt.detail.xhr.status == 401) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  });
});
