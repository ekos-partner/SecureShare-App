# 🚀 Release Notes - SecureShare v2.0

**Core Updates:**

*   **Streamlined Architecture**: Removed the Admin Dashboard, user management, and legacy API key system. The application is now focused exclusively on high-security, zero-knowledge secret sharing via GUI and CLI.
*   **Internal Monitoring Tool**: Introduced `npm run stats`, a server-side utility to extract real-time statistics (secret count, uptime, and system logs) directly from the host or container without exposing data to the web.
*   **Mobile UI Fixes**: Resolved scrolling issues in the "More Information" modal on mobile devices. The interface is now fully responsive and accessible on all screen sizes.
*   **Documentation Overhaul**: Updated README diagrams and security documents to reflect the new simplified architecture, removing all stale references to administrative features and public API branding.
*   **Enhanced Logging**: Implemented a lightweight internal logging system to track system events like secret creation, deletion, and automated cleanups.

**Future Roadmap:**

*   **Optional API Module**: A dedicated **API Module** is currently being prepared as an **optional add-on** for users who require programmatic integration while maintaining the core app's simplicity.

**How to check system stats:**
Run `npm run stats` on your server or `docker exec -it <container_name> npm run stats` within your Docker environment.
