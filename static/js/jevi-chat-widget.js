(function () {
    // Jevi Chat Widget
    class JeviChatWidget {
        constructor(config) {
            this.projectId = config.projectId;
         this.apiUrl = (config.apiUrl 
    || (window.location.hostname === 'localhost'
        ? 'http://localhost:8080'
        : '')
).replace(/\/+$/, '');


            this.position = config.position || 'bottom-right';
            this.theme = config.theme || 'light';
            this.width = config.width || '400px';
            this.height = config.height || '600px';

            this.init();
        }

        init() {
            this.createWidget();
            this.attachEvents();
        }

        createWidget() {
            // Create widget container
            const widgetContainer = document.createElement('div');
            widgetContainer.id = 'jevi-chat-widget';
            widgetContainer.className = `jevi-widget ${this.position} ${this.theme}`;

            // Create chat button
            const chatButton = document.createElement('div');
            chatButton.className = 'jevi-chat-button';
            chatButton.innerHTML = '💬';

            // Create iframe container
            const iframeContainer = document.createElement('div');
            iframeContainer.className = 'jevi-iframe-container';
            iframeContainer.style.display = 'none';

            // Create iframe
            const iframe = document.createElement('iframe');
            iframe.src = `${this.apiUrl}/embed/${this.projectId}`; // ✅ clean path
            iframe.style.width = this.width;
            iframe.style.height = this.height;
            iframe.style.border = 'none';
            iframe.style.borderRadius = '10px';
            iframe.style.boxShadow = '0 4px 20px rgba(0,0,0,0.15)';

            iframeContainer.appendChild(iframe);
            widgetContainer.appendChild(chatButton);
            widgetContainer.appendChild(iframeContainer);

            document.body.appendChild(widgetContainer);

            this.widgetContainer = widgetContainer;
            this.chatButton = chatButton;
            this.iframeContainer = iframeContainer;
        }

        attachEvents() {
            this.chatButton.addEventListener('click', () => {
                this.toggleChat();
            });

            // Close on outside click
            document.addEventListener('click', (e) => {
                if (!this.widgetContainer.contains(e.target)) {
                    this.closeChat();
                }
            });
        }

        toggleChat() {
            const isVisible = this.iframeContainer.style.display !== 'none';
            if (isVisible) {
                this.closeChat();
            } else {
                this.openChat();
            }
        }

        openChat() {
            this.iframeContainer.style.display = 'block';
            this.chatButton.innerHTML = '✕';
        }

        closeChat() {
            this.iframeContainer.style.display = 'none';
            this.chatButton.innerHTML = '💬';
        }
    }

    // Auto-initialize if config is provided
    window.JeviChatWidget = JeviChatWidget;

    // Auto-init if element has attributes
    const autoInit = document.querySelector('[data-jevi-project-id]');
    if (autoInit) {
        const config = {
            projectId: autoInit.getAttribute('data-jevi-project-id'),
            apiUrl: autoInit.getAttribute('data-jevi-api-url'),
            position: autoInit.getAttribute('data-jevi-position'),
            theme: autoInit.getAttribute('data-jevi-theme'),
            width: autoInit.getAttribute('data-jevi-width'),
            height: autoInit.getAttribute('data-jevi-height')
        };

        new JeviChatWidget(config);
    }
})();
