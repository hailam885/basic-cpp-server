function toggleMode() {
    document.body.classList.toggle("dark-mode");
    // Optionally persist choice:
    if (document.body.classList.contains("dark-mode")) {
        localStorage.setItem("theme", "dark");
    } else {
        localStorage.setItem("theme", "light");
    }
}
// Load theme from localStorage
if (localStorage.getItem("theme") === "dark") {
    document.body.classList.add("dark-mode");
}