function scrollToSection(id) {
    const section = document.getElementById(id);
    if (section) section.scrollIntoView({ behavior: "smooth" });
}

// Dark Mode Toggle
const toggleBtn = document.getElementById("theme-toggle");
const userPref = localStorage.getItem("theme");

if (userPref === "dark") {
    document.body.classList.add("dark");
    toggleBtn.textContent = "☀️";
}

toggleBtn.addEventListener("click", () => {
    document.body.classList.toggle("dark");
    const isDark = document.body.classList.contains("dark");
    toggleBtn.textContent = isDark ? "☀️" : "🌙";
    localStorage.setItem("theme", isDark ? "dark" : "light");
});

// Scroll-triggered animations
const animatedElements = document.querySelectorAll(".animate");

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target); // Animate only once
        }
    });
}, { threshold: 0.15 });

animatedElements.forEach(el => observer.observe(el));

document.addEventListener("DOMContentLoaded", () => {
    console.log("SwiftHost landing page ready with dark mode + animations 🚀");
});
