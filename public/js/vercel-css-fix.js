/**
 * Vercel CSS Fix - A robust solution for CSS loading issues in Vercel deployments
 *
 * This script provides multiple fallback methods to ensure CSS files are properly loaded
 * in Vercel's serverless environment, addressing common CSS loading issues.
 */

(function() {
  // Execute on DOMContentLoaded to ensure DOM is ready
  document.addEventListener('DOMContentLoaded', function() {
    // Give a small delay to allow normal CSS loading to happen first
    setTimeout(checkAndFixCSS, 300);
  });

  function checkAndFixCSS() {
    console.log('Vercel CSS Fix: Checking if CSS loaded properly...');

    // Check if ios-style.css loaded correctly
    const cssFiles = ['ios-style.css', 'auth.css'];
    let allCssLoaded = true;

    for (const cssFile of cssFiles) {
      if (document.querySelector(`link[href*="${cssFile}"]`) && !isStylesheetLoaded(cssFile)) {
        console.log(`Vercel CSS Fix: ${cssFile} failed to load properly`);
        allCssLoaded = false;
        fixCSS(cssFile);
      }
    }

    if (allCssLoaded) {
      console.log('Vercel CSS Fix: All CSS files loaded correctly');
    }
  }

  function isStylesheetLoaded(filename) {
    for (let i = 0; i < document.styleSheets.length; i++) {
      try {
        const sheet = document.styleSheets[i];
        // Check if this stylesheet is the one we're looking for
        if (sheet.href && sheet.href.includes(filename)) {
          // Try to access rules to verify the stylesheet loaded properly
          const rules = sheet.cssRules || sheet.rules;
          return rules.length > 0;
        }
      } catch (e) {
        // CORS error or stylesheet didn't load properly
        if (document.styleSheets[i].href && document.styleSheets[i].href.includes(filename)) {
          console.log(`Vercel CSS Fix: CORS issue detected with ${filename}`);
          return false;
        }
      }
    }
    return false;
  }

  function fixCSS(cssFile) {
    console.log(`Vercel CSS Fix: Attempting to fix ${cssFile}...`);

    // Try multiple loading methods in sequence
    loadFromAbsolutePath(cssFile)
      .catch(() => loadFromGitHub(cssFile))
      .catch(() => injectCriticalCSS(cssFile))
      .catch(error => {
        console.error(`Vercel CSS Fix: All methods failed for ${cssFile}`, error);
      });
  }

  function loadFromAbsolutePath(cssFile) {
    return new Promise((resolve, reject) => {
      console.log(`Vercel CSS Fix: Trying absolute path for ${cssFile}`);
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = `/css/${cssFile}?t=${Date.now()}`; // Add timestamp to bypass cache

      link.onload = () => {
        console.log(`Vercel CSS Fix: Successfully loaded ${cssFile} from absolute path`);
        resolve();
      };

      link.onerror = () => {
        console.log(`Vercel CSS Fix: Failed to load ${cssFile} from absolute path`);
        reject();
      };

      document.head.appendChild(link);
    });
  }

  function loadFromGitHub(cssFile) {
    return new Promise((resolve, reject) => {
      console.log(`Vercel CSS Fix: Trying GitHub fallback for ${cssFile}`);

      fetch(`https://raw.githubusercontent.com/jayashish05/Code-Collab-Beta-v1/main/public/css/${cssFile}`)
        .then(response => {
          if (!response.ok) {
            throw new Error('Network response was not ok');
          }
          return response.text();
        })
        .then(css => {
          // Create a new style element with the fetched CSS
          const style = document.createElement('style');
          style.setAttribute('data-source', 'github-fallback');
          style.textContent = css;
          document.head.appendChild(style);
          console.log(`Vercel CSS Fix: Successfully loaded ${cssFile} from GitHub`);
          resolve();
        })
        .catch(error => {
          console.error(`Vercel CSS Fix: Failed to load ${cssFile} from GitHub:`, error);
          reject(error);
        });
    });
  }

  function injectCriticalCSS(cssFile) {
    return new Promise((resolve, reject) => {
      console.log(`Vercel CSS Fix: Injecting critical CSS for ${cssFile}`);

      let criticalCSS = '';

      // Add critical CSS for specific files
      if (cssFile === 'ios-style.css') {
        criticalCSS = `
          :root {
            --ios-primary: #007aff;
            --ios-background: rgba(255, 255, 255, 0.85);
            --ios-card-bg: rgba(255, 255, 255, 0.85);
            --ios-dark-background: rgba(28, 28, 30, 0.85);
            --ios-dark-card-bg: rgba(44, 44, 46, 0.9);
          }

          body {
            background-color: #0f172a;
            color: white;
            font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Helvetica Neue", Helvetica, Arial, sans-serif;
          }

          .spline-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
          }

          .ios-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 2rem;
            position: relative;
            z-index: 1;
          }

          .ios-card {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 2rem;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.15);
          }

          .ios-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            font-weight: 500;
            border-radius: 10px;
            border: none;
            cursor: pointer;
            text-decoration: none;
          }

          .ios-btn-primary {
            background-color: #007aff;
            color: white;
          }

          .ios-feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
            margin: 3rem 0;
          }
        `;
      } else if (cssFile === 'auth.css') {
        criticalCSS = `
          .auth-container {
            display: flex;
            min-height: 100vh;
            align-items: center;
            justify-content: center;
          }

          .auth-card {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 2rem;
            width: 100%;
            max-width: 420px;
          }

          .auth-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            text-align: center;
          }

          .auth-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
          }

          .form-group {
            margin-bottom: 1rem;
          }

          .auth-input {
            width: 100%;
            padding: 0.75rem 1rem;
            font-size: 1rem;
            border-radius: 10px;
            border: 1px solid rgba(0, 0, 0, 0.1);
          }

          .auth-btn {
            width: 100%;
            padding: 0.75rem;
            background: #007aff;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
          }
        `;
      }

      if (criticalCSS) {
        const style = document.createElement('style');
        style.setAttribute('data-source', 'critical-css-fallback');
        style.textContent = criticalCSS;
        document.head.appendChild(style);
        console.log(`Vercel CSS Fix: Injected critical CSS for ${cssFile}`);
        resolve();
      } else {
        reject(new Error(`No critical CSS defined for ${cssFile}`));
      }
    });
  }
})();
