// Mobile menu toggle with animation
document.querySelector('.hamburger').addEventListener('click', function() {
    const navLinks = document.querySelector('.nav-links');
    navLinks.classList.toggle('show');
    this.classList.toggle('active');
    
    // Change icon from bars to X when active
    if (this.classList.contains('active')) {
        this.innerHTML = '<i class="fas fa-times"></i>';
    } else {
        this.innerHTML = '<i class="fas fa-bars"></i>';
    }
});

// Close alerts
document.querySelectorAll('.close-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        this.parentElement.style.display = 'none';
    });
});

// Profile dropdown for mobile
if (window.innerWidth < 768) {
    document.querySelector('.profile-btn').addEventListener('click', function(e) {
        e.stopPropagation();
        document.querySelector('.dropdown-content').classList.toggle('show');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        const dropdown = document.querySelector('.dropdown-content');
        const profileBtn = document.querySelector('.profile-btn');
        
        if (!e.target.closest('.profile-dropdown') && dropdown.classList.contains('show')) {
            dropdown.classList.remove('show');
        }
        
        // For mobile - close menu when clicking outside
        if (window.innerWidth <= 768) {
            const navLinks = document.querySelector('.nav-links');
            const hamburger = document.querySelector('.hamburger');
            
            if (!e.target.closest('.navbar') && navLinks.classList.contains('show')) {
                navLinks.classList.remove('show');
                hamburger.classList.remove('active');
                hamburger.innerHTML = '<i class="fas fa-bars"></i>';
            }
        }
    });
}

// Form validation
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        let valid = true;
        
        this.querySelectorAll('[required]').forEach(input => {
            if (!input.value.trim()) {
                valid = false;
                input.style.borderColor = 'var(--critical)';
            }
        });
        
        if (!valid) {
            e.preventDefault();
            alert('Please fill in all required fields');
        }
    });
});

// Reset input styles on focus
document.querySelectorAll('input').forEach(input => {
    input.addEventListener('focus', function() {
        this.style.borderColor = '';
    });
});