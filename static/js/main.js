/**
 * Professional Portfolio JavaScript Functionality
 * Handles theme switching, navigation, form validation, and user interactions
 * with security best practices and performance optimizations
 */

document.addEventListener('DOMContentLoaded', function() {
    // Theme management with localStorage persistence
    const themeToggle = document.getElementById('theme-toggle');
    const html = document.documentElement;
    
    // Initialize theme from localStorage with error handling
    let savedTheme;
    try {
        savedTheme = localStorage.getItem('theme') || 'dark';
    } catch (e) {
        console.warn('localStorage not available, using default theme');
        savedTheme = 'dark';
    }
    html.classList.toggle('dark', savedTheme === 'dark');
    
    // Theme toggle event listener with null check
    themeToggle?.addEventListener('click', function() {
        const isDark = html.classList.contains('dark');
        html.classList.toggle('dark', !isDark);
        try {
            localStorage.setItem('theme', !isDark ? 'dark' : 'light');
        } catch (e) {
            console.warn('Could not save theme preference');
        }
    });
    
    // Mobile menu toggle functionality
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    
    // Mobile menu toggle with accessibility support
    mobileMenuToggle?.addEventListener('click', function() {
        mobileMenu?.classList.toggle('hidden');
        const isOpen = !mobileMenu?.classList.contains('hidden');
        this.setAttribute('aria-expanded', isOpen.toString());
    });
    
    // Close mobile menu when clicking outside - with null checks
    document.addEventListener('click', function(e) {
        if (mobileMenu && mobileMenuToggle && 
            !mobileMenu.contains(e.target) && 
            !mobileMenuToggle.contains(e.target)) {
            mobileMenu.classList.add('hidden');
            mobileMenuToggle.setAttribute('aria-expanded', 'false');
        }
    });
    
    // Smooth scrolling with offset for fixed header
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const target = document.querySelector(targetId);
            
            if (target) {
                const headerOffset = 80;
                const elementPosition = target.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
                
                // Close mobile menu if open
                mobileMenu?.classList.add('hidden');
                mobileMenuToggle?.setAttribute('aria-expanded', 'false');
            }
        });
    });
    
    // Active navigation highlighting with cached section positions
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link');
    let sectionPositions = [];
    
    // Cache section positions for performance
    function updateSectionPositions() {
        sectionPositions = Array.from(sections).map(section => ({
            id: section.getAttribute('id'),
            top: section.offsetTop
        }));
    }
    
    // Update positions on load and resize
    updateSectionPositions();
    window.addEventListener('resize', updateSectionPositions);
    
    /**
     * Highlights the current navigation item based on scroll position
     */
    function highlightNavigation() {
        let current = '';
        const scrollPos = window.pageYOffset + 200;
        
        for (const section of sectionPositions) {
            if (scrollPos >= section.top) {
                current = section.id;
            }
        }
        
        navLinks.forEach(link => {
            link.classList.remove('text-blue-600', 'dark:text-blue-400');
            const href = link.getAttribute('href');
            if (href === `#${current}` || href?.endsWith(`#${current}`)) {
                link.classList.add('text-blue-600', 'dark:text-blue-400');
            }
        });
    }
    
    // Throttled scroll handler for performance optimization
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (scrollTimeout) {
            window.cancelAnimationFrame(scrollTimeout);
        }
        scrollTimeout = window.requestAnimationFrame(highlightNavigation);
    });
    
    // Enhanced form handling with CSRF protection and validation
    const contactForm = document.querySelector('#contact form');
    if (contactForm) {
        const submitButton = contactForm.querySelector('button[type="submit"]');
        const originalText = submitButton?.textContent;
        
        contactForm.addEventListener('submit', function(e) {
            // Get form elements with null checks
            const nameField = this.querySelector('#name');
            const emailField = this.querySelector('#email');
            const messageField = this.querySelector('#message');
            const csrfToken = this.querySelector('input[name="csrf_token"]');
            
            // Validate form elements exist
            if (!nameField || !emailField || !messageField) {
                e.preventDefault();
                showNotification('Form validation error: Required fields not found.', 'error');
                return;
            }
            
            // Validate CSRF token exists
            if (!csrfToken || !csrfToken.value) {
                e.preventDefault();
                showNotification('Security token missing. Please refresh the page.', 'error');
                return;
            }
            
            // Client-side validation with security considerations
            const name = nameField.value.trim();
            const email = emailField.value.trim();
            const message = messageField.value.trim();
            
            // Validate name (minimum 2 characters, maximum 100)
            if (!name || name.length < 2 || name.length > 100) {
                e.preventDefault();
                showNotification('Please enter a valid name (2-100 characters).', 'error');
                return;
            }
            
            // Validate email format and length
            if (!email || !isValidEmail(email) || email.length > 255) {
                e.preventDefault();
                showNotification('Please enter a valid email address.', 'error');
                return;
            }
            
            // Validate message (minimum 10 characters, maximum 1000)
            if (!message || message.length < 10 || message.length > 1000) {
                e.preventDefault();
                showNotification('Please enter a message (10-1000 characters).', 'error');
                return;
            }
            
            // Show loading state to prevent double submission
            if (submitButton) {
                submitButton.textContent = 'Sending...';
                submitButton.disabled = true;
                submitButton.classList.add('opacity-75');
                
                // Reset button state after timeout (fallback)
                setTimeout(() => {
                    submitButton.textContent = originalText;
                    submitButton.disabled = false;
                    submitButton.classList.remove('opacity-75');
                }, 10000);
            }
        });
    }
    
    // Auto-hide flash messages with smooth animation
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach((message, index) => {
        setTimeout(() => {
            message.style.transform = 'translateX(100%)';
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 300);
        }, 5000 + (index * 500)); // Stagger multiple messages
    });
    
    // Intersection Observer for scroll-triggered animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in-up');
                observer.unobserve(entry.target); // Only animate once for performance
            }
        });
    }, observerOptions);
    
    // Observe elements for scroll-triggered animations
    document.querySelectorAll('section, .project-card, .skill-card').forEach(el => {
        observer.observe(el);
    });
    
    // Copy to clipboard functionality for contact information
    const contactItems = document.querySelectorAll('#contact .flex.items-center span, #contact .flex.items-center a');
    contactItems.forEach(item => {
        item.style.cursor = 'pointer';
        item.title = 'Click to copy'; // Accessibility improvement
        
        item.addEventListener('click', async function(e) {
            e.preventDefault();
            const text = this.textContent.trim();
            
            try {
                // Modern clipboard API with error handling
                await navigator.clipboard.writeText(text);
                showNotification(`Copied: ${text}`, 'success');
            } catch (err) {
                // Fallback for older browsers or when clipboard API fails
                try {
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    textArea.style.position = 'fixed';
                    textArea.style.opacity = '0';
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    showNotification(`Copied: ${text}`, 'success');
                } catch (fallbackErr) {
                    showNotification('Copy failed. Please select and copy manually.', 'error');
                }
            }
        });
    });
    
    /**
     * Validates email format using simplified but effective regex
     * @param {string} email - Email address to validate
     * @returns {boolean} - True if email is valid
     */
    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    /**
     * Shows a notification message with auto-dismiss
     * @param {string} message - Message to display
     * @param {string} type - Notification type (success, error, info)
     */
    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-20 right-4 z-50 px-6 py-3 rounded-lg shadow-lg transform transition-all duration-300 ${
            type === 'success' ? 'bg-green-500' : type === 'error' ? 'bg-red-500' : 'bg-blue-500'
        } text-white max-w-sm`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
            notification.style.opacity = '1';
        }, 100);
        
        // Auto remove with cleanup
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            notification.style.opacity = '0';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
    
    // Security: Add CSP violation reporting (if CSP is implemented)
    document.addEventListener('securitypolicyviolation', function(e) {
        console.warn('CSP Violation:', e.violatedDirective, e.blockedURI);
    });
});