import os
import logging
import pytz
from datetime import datetime, timedelta
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_migrate import Migrate
from flask_mail import Mail
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the Base class
db = SQLAlchemy(model_class=Base)

# Initialize Flask-Migrate
migrate = Migrate()

# Initialize Flask-Mail
mail = Mail()

# Initialize Flask-Login
login_manager = LoginManager()

# Initialize CSRF Protection
csrf = CSRFProtect()

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration from config.py
    app.config.from_object('config.Config')
    
    # Apply centralized database optimization (fixes SSL errors and connection pooling)
    try:
        from database_connection_optimizer import initialize_database_optimization
        initialize_database_optimization(app)
        logger.info("✅ Centralized database optimization applied")
    except ImportError as e:
        logger.warning(f"Database optimization not available: {e}")
        # Fallback to deployment config
        from deployment_config import DeploymentConfig
        DeploymentConfig.configure_app(app)
    
    # Set secret key with deployment optimization
    app.secret_key = os.environ.get("SESSION_SECRET", "antidote_secret_key")
    
    # Optimize startup environment
    try:
        from startup_workflow_config import optimize_environment_for_startup
        optimize_environment_for_startup()
        logger.info("✅ Environment optimized for deployment")
    except ImportError:
        logger.info("ℹ️ Startup workflow config not available")
    
    # Set timezone to IST (India Standard Time)
    app.config['TIMEZONE'] = pytz.timezone('Asia/Kolkata')
    
    # Increase CSRF token expiration time to 1 hour
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour in seconds
    
    # Configure email settings
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'antidote.platform@gmail.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'antidote.platform@gmail.com')
    
    # Use ProxyFix middleware for proper URL generation
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Register comprehensive security headers
    try:
        from security_headers import register_security_middleware
        register_security_middleware(app)
        logger.info("✅ Security headers middleware enabled")
    except ImportError as e:
        logger.warning(f"Security headers middleware not available: {e}")
    
    # Apply comprehensive performance optimizations
    try:
        from server_performance_optimization import initialize_performance_optimization
        initialize_performance_optimization(app)
        logger.info("Performance optimization system initialized successfully")
    except ImportError as e:
        logger.warning(f"Performance optimization system not available: {e}")
    
    # Apply safe performance optimizations (backend-only, no visual changes)
    try:
        from safe_performance_optimization import register_safe_performance_optimizations
        register_safe_performance_optimizations(app)
    except ImportError as e:
        logger.warning(f"Safe performance optimizations not available: {e}")
    
    # Phase 1 performance optimizations will be initialized after app context is created
    
    # Phase 2 performance optimizations
    try:
        from phase2_css_optimizer import css_optimizer
        from phase2_static_optimizer import static_optimizer
        
        # Initialize static asset optimization
        static_optimizer.init_app(app)
        
        # Add template context for CSS optimization
        @app.context_processor
        def inject_css_optimization():
            return {
                'critical_css_inline': css_optimizer.get_critical_css_inline(),
                'non_critical_css_files': css_optimizer.get_non_critical_css_files()
            }
        
        logger.info("Phase 2 CSS and static asset optimizations initialized")
        
    except ImportError as e:
        logger.warning(f"Phase 2 optimizations not available: {e}")
    
    # Phase 3 performance optimizations
    try:
        from phase3_server_optimizer import ServerResponseOptimizer
        
        # Initialize server response optimization
        server_optimizer = ServerResponseOptimizer()
        server_optimizer.init_app(app)
        
        logger.info("Phase 3 server response optimizations initialized")
        
    except ImportError as e:
        logger.warning(f"Phase 3 optimizations not available: {e}")
    
    # Register responsive image routes
    try:
        from responsive_image_routes import responsive_images, register_image_helpers
        
        # Register blueprint
        app.register_blueprint(responsive_images)
        
        # Register template helpers
        register_image_helpers(app)
        
        logger.info("Responsive image serving initialized")
        
    except ImportError as e:
        logger.warning(f"Responsive image routes not available: {e}")
    
    # Phase 4A: Static Asset Optimization - Disabled to prevent conflicts
    # try:
    #     from static_asset_optimizer import static_optimizer
    #     
    #     # Initialize static asset optimization
    #     static_optimizer.init_app(app)
    #     
    #     logger.info("Phase 4A static asset optimization initialized")
    #     
    # except ImportError as e:
    #     logger.warning(f"Phase 4A static asset optimization not available: {e}")
    logger.info("Phase 4A static asset optimization disabled to prevent endpoint conflicts")
    
    # Phase 4A Regression Fix: Server Response Optimization
    try:
        from server_response_fix import server_optimizer
        
        # Initialize server response optimization
        server_optimizer.init_app(app)
        
        logger.info("Phase 4A server response optimization initialized")
        
    except ImportError as e:
        logger.warning(f"Phase 4A server response optimization not available: {e}")
    
    # Apply advanced performance optimizations (CSS bundling, image optimization)
    try:
        from advanced_performance_system import register_advanced_performance_optimizations
        register_advanced_performance_optimizations(app)
    except ImportError as e:
        logger.warning(f"Advanced performance optimizations not available: {e}")
    
    # Apply critical performance optimizations (single query optimization + caching)
    try:
        from critical_performance_fix import register_critical_performance_optimizations
        register_critical_performance_optimizations(app)
        logger.info("✅ Critical performance optimizations registered")
    except ImportError as e:
        logger.warning(f"Critical performance optimizations not available: {e}")
    
    # Apply CSS render-blocking optimizations (critical CSS inlining + async loading)
    try:
        from css_render_blocking_fix import register_css_optimization
        register_css_optimization(app)
        logger.info("✅ CSS render-blocking optimization registered")
    except ImportError as e:
        logger.warning(f"CSS render-blocking optimization not available: {e}")
    
    # Resolve middleware conflicts (disable redundant performance modules)
    try:
        from middleware_conflict_resolver import register_middleware_conflict_resolution
        register_middleware_conflict_resolution(app)
        logger.info("✅ Middleware conflicts resolved")
    except ImportError as e:
        logger.warning(f"Middleware conflict resolution not available: {e}")
    
    # Apply targeted doctors route optimization
    try:
        from doctors_route_optimizer import register_optimized_doctors_route
        register_optimized_doctors_route(app)
        logger.info("⚡ Optimized doctors route registered")
    except ImportError as e:
        logger.warning(f"Doctors route optimization not available: {e}")
    
    # Apply final route optimizations for remaining slow pages  
    try:
        from final_route_optimizer import register_final_optimizations
        register_final_optimizations(app)
        logger.info("🚀 Final route optimizations registered")
    except ImportError as e:
        logger.warning(f"Final route optimizations not available: {e}")
    
    # Auto production optimizer DISABLED - conflicts with centralized database config
    # try:
    #     from auto_production_optimizer import register_auto_production_optimizer
    #     register_auto_production_optimizer(app)
    #     logger.info("🚀 Auto production optimizations registered")
    # except ImportError as e:
    #     logger.warning(f"Auto production optimizations not available: {e}")
    logger.info("ℹ️ Auto production optimizer disabled - using centralized database config")
    
    # Apply manual production optimizations (fallback)
    try:
        from production_performance_optimizer import register_production_optimizations
        register_production_optimizations(app)
        logger.info("🏭 Manual production optimizations registered")
    except ImportError as e:
        logger.warning(f"Manual production optimizations not available: {e}")
    
    # Apply server response optimizations (reduce response time <200ms)
    try:
        from server_response_optimization import register_server_response_optimizations
        register_server_response_optimizations(app)
    except ImportError as e:
        logger.warning(f"Server response optimizations not available: {e}")
    
    # Mobile 100% Performance Score Optimization
    try:
        from mobile_100_performance import register_mobile_100_performance
        register_mobile_100_performance(app)
        logger.info("🚀 Mobile 100% performance optimization registered")
    except ImportError as e:
        logger.warning(f"Mobile 100% performance optimization not available: {e}")
    
    # Ultra-Fast Mobile Cache System
    try:
        from ultra_fast_mobile_cache import register_ultra_fast_mobile_cache
        register_ultra_fast_mobile_cache(app)
        logger.info("⚡ Ultra-fast mobile cache system registered")
    except ImportError as e:
        logger.warning(f"Ultra-fast mobile cache system not available: {e}")
    
    # Mobile Performance Optimizer
    try:
        from mobile_performance_optimizer import register_mobile_performance_optimization
        register_mobile_performance_optimization(app)
        logger.info("📱 Mobile performance optimizer registered")
    except ImportError as e:
        logger.warning(f"Mobile performance optimizer not available: {e}")
    
    # Emergency fix for antidote.fit performance issues (20-50x slower)
    try:
        from deployment_performance_fix import apply_emergency_production_fixes
        apply_emergency_production_fixes(app)
        logger.info("🚀 Emergency production performance fixes applied")
    except ImportError as e:
        logger.warning(f"Emergency production fixes not available: {e}")
    except Exception as e:
        logger.error(f"❌ Failed to apply emergency production fixes: {e}")
    
    # Apply comprehensive production emergency fix
    try:
        from production_emergency_fix import register_production_emergency_fix
        register_production_emergency_fix(app)
        logger.info("🚀 Comprehensive production emergency fixes applied")
    except ImportError as e:
        logger.warning(f"Comprehensive production emergency fixes not available: {e}")
    except Exception as e:
        logger.error(f"❌ Failed to apply comprehensive production emergency fixes: {e}")
    
    # Force production configuration as final step
    try:
        from force_production_config import register_forced_production_config
        register_forced_production_config(app)
        logger.info("🔥 Forced production configuration applied")
    except ImportError as e:
        logger.warning(f"Forced production configuration not available: {e}")
    except Exception as e:
        logger.error(f"❌ Failed to apply forced production configuration: {e}")
    
    # Final production fix DISABLED - conflicts with centralized database config (pool_size=50 vs 25)
    # try:
    #     from final_production_fix import register_final_production_fix
    #     register_final_production_fix(app)
    #     logger.info("🚀 Final production performance fix applied")
    # except ImportError as e:
    #     logger.warning(f"Final production performance fix not available: {e}")
    # except Exception as e:
    #     logger.error(f"❌ Failed to apply final production performance fix: {e}")
    logger.info("ℹ️ Final production fix disabled - using centralized database config")
    
    # Removed unused mobile performance optimizers
    
    # Register custom Jinja2 filters
    from utils.time_filters import ago
    app.jinja_env.filters['ago'] = ago
    
    # Comprehensive sitemap disabled - using optimized sitemap index in routes.py instead
    # This prevents timeout issues and improves GSC compatibility
    

    
    # Initialize SQLAlchemy with the app
    db.init_app(app)
    
    # Initialize Flask-Migrate
    migrate.init_app(app, db)
    
    # ========== PERFORMANCE OPTIMIZATIONS ==========
    # Enable compression middleware for better performance
    try:
        from compression_middleware import enable_compression
        enable_compression(app)
        logger.info("✅ Compression middleware enabled")
    except ImportError:
        logger.warning("Compression middleware not available")
    
    # Register optimized static file serving
    try:
        from optimized_static_server import register_optimized_static
        register_optimized_static(app)
        logger.info("✅ Optimized static file serving enabled")
    except ImportError:
        logger.warning("Optimized static server not available")
    
    # Register performance configuration
    try:
        from performance_config import register_performance_context
        register_performance_context(app)
        logger.info("✅ Performance configuration registered")
    except ImportError:
        logger.warning("Performance configuration not available")
    
    # Initialize Flask-Mail
    mail.init_app(app)
    
    # Initialize Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'web.login'
    login_manager.login_message = 'Please log in to access this page'
    login_manager.login_message_category = 'info'
    
    # Initialize CSRF Protection with exemptions
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    # Configure CSRF exemptions for specific endpoints
    @csrf.exempt
    @app.route('/api/track-interaction', methods=['POST'])
    def api_track_interaction():
        """CSRF-exempt tracking endpoint for personalization."""
        try:
            from personalization_service import PersonalizationService
            from flask import request
            
            # Get data from either JSON or form data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()
                
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400
            
            fingerprint = data.get('fingerprint')
            interaction_type = data.get('interaction_type')
            content_type = data.get('content_type')
            content_id = data.get('content_id', 0)
            content_name = data.get('content_name', '')
            page_url = data.get('page_url', '')
            session_id = data.get('session_id', '')
            
            if not fingerprint or not interaction_type or not content_type:
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
            # Track the interaction
            try:
                PersonalizationService.track_interaction(
                    fingerprint, interaction_type, content_type, int(content_id), 
                    content_name, page_url
                )
            except Exception as e:
                app.logger.warning(f"Failed to track interaction: {e}")
                # Continue without failing the request
            
            return jsonify({'success': True})
            
        except Exception as e:
            print(f"Error tracking interaction: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # Additional CSRF exemptions for banner API endpoints
    @csrf.exempt 
    @app.route('/api/banners/impression', methods=['POST'])
    def api_banner_impression():
        """CSRF-exempt banner impression tracking."""
        from flask import request
        try:
            data = request.get_json()
            if not data or 'slide_id' not in data:
                return jsonify({'success': False, 'message': 'Missing slide_id'}), 400
            
            from models import BannerSlide
            slide_id = data['slide_id']
            slide = BannerSlide.query.get(slide_id)
            
            if not slide:
                return jsonify({'success': False, 'message': 'Slide not found'}), 404
            
            # Initialize impression count if None
            if slide.impression_count is None:
                slide.impression_count = 0
            
            slide.impression_count += 1
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Impression recorded for slide {slide_id}',
                'impression_count': slide.impression_count
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    @csrf.exempt
    @app.route('/api/banners/click', methods=['POST'])
    def api_banner_click():
        """CSRF-exempt banner click tracking."""
        try:
            data = request.get_json()
            if not data or 'slide_id' not in data:
                return jsonify({'success': False, 'message': 'Missing slide_id'}), 400
        
            from models import BannerSlide
            slide_id = data['slide_id']
            slide = BannerSlide.query.get(slide_id)
            
            if not slide:
                return jsonify({'success': False, 'message': 'Slide not found'}), 404
            
            # Initialize impression count to avoid division by zero
            if slide.impression_count is None:
                slide.impression_count = 1
            
            slide.click_count += 1
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Click recorded for slide {slide_id}',
                'click_count': slide.click_count,
                'ctr': round((slide.click_count / slide.impression_count * 100), 2) if slide.impression_count > 0 else 0
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        try:
            # Use a fresh session for user loading to avoid transaction conflicts
            user = db.session.get(User, int(user_id))
            if user:
                db.session.expunge(user)  # Detach from session to avoid conflicts
            return user
        except Exception as e:
            # Enhanced error handling for Supabase connection issues
            app.logger.warning(f"Primary user load failed for user {user_id}: {e}")
            try:
                # Force session rollback and close
                db.session.rollback()
                db.session.close()
                
                # Create fresh session for retry
                from sqlalchemy import text
                result = db.session.execute(text("SELECT * FROM users WHERE id = :user_id"), {"user_id": int(user_id)}).fetchone()
                if result:
                    user_data = dict(result._mapping)
                    # Create a minimal User object for session management
                    user = User()
                    user.id = user_data['id']
                    user.email = user_data['email']
                    user.role = user_data['role']
                    user.name = user_data['name']
                    return user
            except Exception as e2:
                app.logger.error(f"Fallback user load failed for user {user_id}: {e2}")
                try:
                    db.session.rollback()
                    db.session.close()
                except:
                    pass
            return None
    
    # Initialize deployment startup optimizer for fast health checks
    from deployment_startup_fix import deployment_optimizer
    deployment_optimizer.init_app(app, db)
    
    # Register essential blueprints first (non-blocking)
    with app.app_context():
        # Register unified clinic dashboard blueprint first
        try:
            from unified_clinic_dashboard import unified_clinic_bp
            app.register_blueprint(unified_clinic_bp)
            logger.info("Unified clinic dashboard blueprint registered")
        except ImportError as e:
            logger.warning(f"Unified clinic dashboard not available: {e}")
        
        # Register routes for immediate functionality
        from routes import register_routes
        register_routes(app)
        logger.info("✅ Core routes registered successfully")
        
        # Register advanced SEO system for top Google rankings
        try:
            from advanced_seo_routes import advanced_seo_bp
            app.register_blueprint(advanced_seo_bp)
            logger.info("✅ Advanced SEO system registered")
        except ImportError as e:
            logger.warning(f"Advanced SEO system not available: {e}")
        
        # Register medical content optimization system
        try:
            from medical_content_optimizer import medical_content_bp
            app.register_blueprint(medical_content_bp)
            logger.info("✅ Medical content optimizer registered")
        except ImportError as e:
            logger.warning(f"Medical content optimizer not available: {e}")
        
        # Register local SEO system for city-specific rankings
        try:
            from local_seo_system import local_seo_bp
            app.register_blueprint(local_seo_bp)
            logger.info("✅ Local SEO system registered")
        except ImportError as e:
            logger.warning(f"Local SEO system not available: {e}")
        
        # Register enhanced procedure templates for comprehensive SEO content
        try:
            from enhanced_procedure_templates import enhanced_procedures_bp
            app.register_blueprint(enhanced_procedures_bp)
            logger.info("✅ Enhanced procedure templates registered")
        except ImportError as e:
            logger.warning(f"Enhanced procedure templates not available: {e}")
        
        # Register link building & authority system for market domination
        try:
            from link_building_system import link_building_bp
            app.register_blueprint(link_building_bp)
            logger.info("✅ Link building & authority system registered")
        except ImportError as e:
            logger.warning(f"Link building system not available: {e}")
        
        # Register health monitoring endpoints (backup)
        try:
            from health_monitoring import register_health_monitoring
            register_health_monitoring(app)
        except ImportError as e:
            logger.warning(f"Additional health monitoring not available: {e}")
        
        logger.info("🚀 App ready for requests - initialization continues in background")
    
    # Register sitemap WSGI robots header fix (operates at WSGI level, below Flask middleware)
    try:
        from sitemap_wsgi_fix import register_sitemap_wsgi_fix
        register_sitemap_wsgi_fix(app)
    except ImportError as e:
        logger.warning(f"Sitemap WSGI robots fix not available: {e}")
    
    return app
