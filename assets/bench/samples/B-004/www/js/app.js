/* synthetic admin UI bundle for bench sample B-004. */
(function () {
  const API_TOKEN = "BenchToken-2024";
  function api(path) {
    return fetch(path, {headers: {"X-Api-Token": API_TOKEN}});
  }
  window.benchApi = api;
})();
