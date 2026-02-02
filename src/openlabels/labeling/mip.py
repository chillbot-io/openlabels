"""
Microsoft Information Protection (MIP) SDK wrapper.

Provides integration with MIP SDK for applying sensitivity labels to files.
Uses pythonnet to call the .NET MIP SDK.

Requirements:
    - pythonnet >= 3.0
    - MIP SDK NuGet packages:
      - Microsoft.InformationProtection.File
      - Microsoft.InformationProtection.Policy
    - Azure AD app registration with MIP permissions:
      - InformationProtectionPolicy.Read.All
      - InformationProtectionPolicy.Read

Usage:
    mip = MIPClient(
        client_id="...",
        client_secret="...",
        tenant_id="...",
        mip_sdk_path="/path/to/mip/assemblies",
    )
    await mip.initialize()

    labels = await mip.get_labels()
    await mip.apply_label(file_path, label_id)
"""

import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable
from functools import partial

logger = logging.getLogger(__name__)

# Check for pythonnet availability
try:
    import clr
    PYTHONNET_AVAILABLE = True
except ImportError:
    PYTHONNET_AVAILABLE = False
    clr = None

# MIP SDK loaded flag
_MIP_ASSEMBLIES_LOADED = False


@dataclass
class SensitivityLabel:
    """A sensitivity label from MIP."""
    id: str
    name: str
    description: str
    tooltip: str
    color: Optional[str] = None
    priority: int = 0
    parent_id: Optional[str] = None
    is_active: bool = True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tooltip": self.tooltip,
            "color": self.color,
            "priority": self.priority,
            "parent_id": self.parent_id,
            "is_active": self.is_active,
        }


@dataclass
class LabelingResult:
    """Result of applying a label."""
    success: bool
    file_path: str
    label_id: Optional[str] = None
    label_name: Optional[str] = None
    error: Optional[str] = None
    was_protected: bool = False
    is_protected: bool = False

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "file_path": self.file_path,
            "label_id": self.label_id,
            "label_name": self.label_name,
            "error": self.error,
            "was_protected": self.was_protected,
            "is_protected": self.is_protected,
        }


def _load_mip_assemblies(mip_sdk_path: Path) -> bool:
    """
    Load MIP SDK .NET assemblies.

    The MIP SDK path should contain:
    - Microsoft.InformationProtection.File.dll
    - Microsoft.InformationProtection.dll
    - mip_dotnet.dll (native wrapper)
    """
    global _MIP_ASSEMBLIES_LOADED

    if _MIP_ASSEMBLIES_LOADED:
        return True

    if not PYTHONNET_AVAILABLE:
        logger.error("pythonnet not installed")
        return False

    if not mip_sdk_path or not mip_sdk_path.exists():
        logger.error(f"MIP SDK path not found: {mip_sdk_path}")
        return False

    try:
        # Add the MIP SDK path to the .NET assembly search path
        sys.path.insert(0, str(mip_sdk_path))

        # Load required assemblies
        required_dlls = [
            "Microsoft.InformationProtection.File.dll",
        ]

        for dll in required_dlls:
            dll_path = mip_sdk_path / dll
            if dll_path.exists():
                clr.AddReference(str(dll_path))
                logger.debug(f"Loaded assembly: {dll}")
            else:
                logger.warning(f"Assembly not found: {dll_path}")

        _MIP_ASSEMBLIES_LOADED = True
        logger.info("MIP SDK assemblies loaded successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to load MIP assemblies: {e}")
        return False


class AuthDelegateImpl:
    """
    Authentication delegate for MIP SDK.

    Acquires OAuth tokens using MSAL for MIP API calls.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self._app = None

    def _get_msal_app(self):
        """Get or create MSAL confidential client."""
        if self._app is None:
            import msal

            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            self._app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=authority,
                client_credential=self.client_secret,
            )
        return self._app

    def acquire_token(self, identity: str, challenge: Any) -> str:
        """
        Acquire OAuth token for MIP.

        Called by MIP SDK when authentication is needed.
        """
        try:
            app = self._get_msal_app()

            # MIP SDK scopes
            scopes = ["https://syncservice.o365syncservice.com/.default"]

            result = app.acquire_token_for_client(scopes=scopes)

            if "access_token" in result:
                return result["access_token"]
            else:
                error = result.get("error_description", "Unknown error")
                logger.error(f"Failed to acquire token: {error}")
                return ""

        except Exception as e:
            logger.error(f"Token acquisition failed: {e}")
            return ""


class MIPClient:
    """
    Client for Microsoft Information Protection SDK.

    Wraps the .NET MIP SDK via pythonnet for label management
    and file labeling operations.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        mip_sdk_path: Optional[Path] = None,
        app_name: str = "OpenLabels",
        app_version: str = "1.0.0",
    ):
        """
        Initialize the MIP client.

        Args:
            client_id: Azure AD application client ID
            client_secret: Azure AD application client secret
            tenant_id: Azure AD tenant ID
            mip_sdk_path: Path to MIP SDK assemblies
            app_name: Application name for MIP registration
            app_version: Application version
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.mip_sdk_path = mip_sdk_path or self._default_sdk_path()
        self.app_name = app_name
        self.app_version = app_version

        self._initialized = False
        self._mip_context = None
        self._file_profile = None
        self._file_engine = None
        self._auth_delegate = None
        self._labels: List[SensitivityLabel] = []

    def _default_sdk_path(self) -> Path:
        """Get default MIP SDK path based on platform."""
        if sys.platform == "win32":
            # Default Windows location
            return Path(os.environ.get("LOCALAPPDATA", "")) / "MIP" / "SDK"
        else:
            # Linux/Mac - typically not supported
            return Path.home() / ".mip" / "sdk"

    @property
    def is_available(self) -> bool:
        """Check if MIP SDK is available."""
        return PYTHONNET_AVAILABLE

    @property
    def is_initialized(self) -> bool:
        """Check if client is initialized."""
        return self._initialized

    async def initialize(self) -> bool:
        """
        Initialize the MIP SDK.

        Loads assemblies, creates MipContext, FileProfile, and FileEngine.

        Returns:
            True if initialized successfully
        """
        if not PYTHONNET_AVAILABLE:
            logger.error("pythonnet not installed. MIP SDK unavailable.")
            return False

        if self._initialized:
            return True

        try:
            # Load assemblies
            if not _load_mip_assemblies(self.mip_sdk_path):
                return False

            # Run initialization in thread pool (blocking .NET calls)
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(None, self._initialize_sync)

            return success

        except Exception as e:
            logger.error(f"Failed to initialize MIP SDK: {e}")
            return False

    def _initialize_sync(self) -> bool:
        """Synchronous MIP initialization (runs in thread pool)."""
        try:
            # Import MIP namespaces (after assemblies are loaded)
            from Microsoft.InformationProtection import (
                MipContext,
                MipConfiguration,
                ApplicationInfo,
                LogLevel,
            )
            from Microsoft.InformationProtection.File import (
                FileProfile,
                FileEngineSettings,
            )

            # Create application info
            app_info = ApplicationInfo()
            app_info.ApplicationId = self.client_id
            app_info.ApplicationName = self.app_name
            app_info.ApplicationVersion = self.app_version

            # Create MIP configuration
            mip_config = MipConfiguration(
                app_info,
                "mip_data",  # Cache directory
                LogLevel.Warning,
                False,  # Is offline
            )

            # Create MIP context
            self._mip_context = MipContext.Create(mip_config)
            logger.info("MipContext created")

            # Create auth delegate
            self._auth_delegate = AuthDelegateImpl(
                self.client_id,
                self.client_secret,
                self.tenant_id,
            )

            # Create file profile settings
            profile_settings = FileProfile.Settings(
                self._mip_context,
                MipContext.CacheStorageType.InMemory,
                self._create_consent_delegate(),
            )

            # Create file profile
            self._file_profile = FileProfile.LoadAsync(profile_settings).GetAwaiter().GetResult()
            logger.info("FileProfile created")

            # Create file engine settings
            engine_settings = FileEngineSettings(
                self.client_id,  # Engine ID
                self._auth_delegate,
                "",  # Client data
                "en-US",  # Locale
            )
            engine_settings.Identity = MipContext.Identity(f"service@{self.tenant_id}")

            # Create file engine
            self._file_engine = self._file_profile.AddEngineAsync(engine_settings).GetAwaiter().GetResult()
            logger.info("FileEngine created")

            self._initialized = True
            return True

        except Exception as e:
            logger.error(f"MIP initialization failed: {e}")
            return False

    def _create_consent_delegate(self):
        """Create a consent delegate that auto-consents."""
        # In production, this might prompt the user
        # For service accounts, we auto-consent
        from Microsoft.InformationProtection import ConsentDelegate

        class AutoConsentDelegate(ConsentDelegate):
            def GetUserConsent(self, url):
                from Microsoft.InformationProtection import Consent
                return Consent.Accept

        return AutoConsentDelegate()

    async def shutdown(self) -> None:
        """Shutdown the MIP client and release resources."""
        if self._file_engine:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._shutdown_sync)
            except Exception as e:
                logger.warning(f"Error during MIP shutdown: {e}")

        self._file_engine = None
        self._file_profile = None
        self._mip_context = None
        self._initialized = False
        logger.info("MIP client shutdown")

    def _shutdown_sync(self) -> None:
        """Synchronous shutdown."""
        if self._file_profile and self._file_engine:
            self._file_profile.UnloadEngineAsync(self._file_engine.Settings.EngineId).GetAwaiter().GetResult()

    async def get_labels(self, force_refresh: bool = False) -> List[SensitivityLabel]:
        """
        Get available sensitivity labels.

        Args:
            force_refresh: Force refresh from MIP service

        Returns:
            List of available labels
        """
        if not self._initialized:
            logger.warning("MIP client not initialized")
            return []

        if self._labels and not force_refresh:
            return self._labels

        try:
            loop = asyncio.get_event_loop()
            labels = await loop.run_in_executor(None, self._get_labels_sync)
            self._labels = labels
            return labels

        except Exception as e:
            logger.error(f"Failed to get labels: {e}")
            return []

    def _get_labels_sync(self) -> List[SensitivityLabel]:
        """Synchronous label fetch."""
        labels = []

        mip_labels = self._file_engine.SensitivityLabels

        for mip_label in mip_labels:
            label = SensitivityLabel(
                id=mip_label.Id,
                name=mip_label.Name,
                description=mip_label.Description or "",
                tooltip=mip_label.Tooltip or "",
                color=mip_label.Color if hasattr(mip_label, 'Color') else None,
                priority=mip_label.Priority if hasattr(mip_label, 'Priority') else 0,
                parent_id=mip_label.Parent.Id if mip_label.Parent else None,
                is_active=mip_label.IsActive if hasattr(mip_label, 'IsActive') else True,
            )
            labels.append(label)

            # Include child labels
            if hasattr(mip_label, 'Children'):
                for child in mip_label.Children:
                    child_label = SensitivityLabel(
                        id=child.Id,
                        name=child.Name,
                        description=child.Description or "",
                        tooltip=child.Tooltip or "",
                        color=child.Color if hasattr(child, 'Color') else None,
                        priority=child.Priority if hasattr(child, 'Priority') else 0,
                        parent_id=mip_label.Id,
                        is_active=child.IsActive if hasattr(child, 'IsActive') else True,
                    )
                    labels.append(child_label)

        return labels

    async def get_label(self, label_id: str) -> Optional[SensitivityLabel]:
        """
        Get a specific label by ID.

        Args:
            label_id: The label GUID

        Returns:
            Label if found, None otherwise
        """
        labels = await self.get_labels()
        for label in labels:
            if label.id == label_id:
                return label
        return None

    async def apply_label(
        self,
        file_path: str,
        label_id: str,
        justification: Optional[str] = None,
        extended_properties: Optional[Dict[str, str]] = None,
    ) -> LabelingResult:
        """
        Apply a sensitivity label to a file.

        Args:
            file_path: Path to the file
            label_id: ID of the label to apply
            justification: Optional justification message (required for downgrade)
            extended_properties: Optional extended properties to include

        Returns:
            LabelingResult indicating success/failure
        """
        if not self._initialized:
            return LabelingResult(
                success=False,
                file_path=file_path,
                error="MIP client not initialized",
            )

        if not Path(file_path).exists():
            return LabelingResult(
                success=False,
                file_path=file_path,
                error="File not found",
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                partial(
                    self._apply_label_sync,
                    file_path,
                    label_id,
                    justification,
                    extended_properties,
                )
            )
            return result

        except Exception as e:
            logger.error(f"Failed to apply label to {file_path}: {e}")
            return LabelingResult(
                success=False,
                file_path=file_path,
                label_id=label_id,
                error=str(e),
            )

    def _apply_label_sync(
        self,
        file_path: str,
        label_id: str,
        justification: Optional[str],
        extended_properties: Optional[Dict[str, str]],
    ) -> LabelingResult:
        """Synchronous label application."""
        from Microsoft.InformationProtection.File import (
            FileHandler,
            LabelingOptions,
        )
        from Microsoft.InformationProtection import (
            AssignmentMethod,
            ActionSource,
        )

        handler = None
        try:
            # Create file handler
            handler = self._file_engine.CreateFileHandler(
                file_path,
                self._create_file_observer(),
            )

            # Check current label
            current_label = handler.Label
            was_protected = handler.Protection is not None if hasattr(handler, 'Protection') else False

            # Create labeling options
            labeling_options = LabelingOptions()
            labeling_options.AssignmentMethod = AssignmentMethod.Standard
            labeling_options.IsDowngradeJustified = justification is not None
            if justification:
                labeling_options.JustificationMessage = justification

            # Apply extended properties if provided
            if extended_properties:
                for key, value in extended_properties.items():
                    labeling_options.ExtendedProperties.Add(key, value)

            # Set the label
            handler.SetLabel(
                self._file_engine.GetLabelById(label_id),
                labeling_options,
                ActionSource.Manual,
            )

            # Commit changes
            committed = handler.CommitAsync(file_path).GetAwaiter().GetResult()

            if committed:
                # Get label name for result
                label = self._file_engine.GetLabelById(label_id)
                label_name = label.Name if label else None

                return LabelingResult(
                    success=True,
                    file_path=file_path,
                    label_id=label_id,
                    label_name=label_name,
                    was_protected=was_protected,
                    is_protected=handler.Protection is not None if hasattr(handler, 'Protection') else False,
                )
            else:
                return LabelingResult(
                    success=False,
                    file_path=file_path,
                    label_id=label_id,
                    error="Commit returned false",
                )

        except Exception as e:
            return LabelingResult(
                success=False,
                file_path=file_path,
                label_id=label_id,
                error=str(e),
            )
        finally:
            # Clean up handler
            if handler:
                try:
                    handler.Dispose()
                except Exception:
                    pass

    def _create_file_observer(self):
        """Create a file handler observer."""
        from Microsoft.InformationProtection.File import IFileHandler

        class FileObserver(IFileHandler.IObserver):
            def OnCreateFileHandlerSuccess(self, handler, context):
                pass

            def OnCreateFileHandlerFailure(self, error, context):
                logger.error(f"File handler creation failed: {error}")

        return FileObserver()

    async def remove_label(self, file_path: str) -> LabelingResult:
        """
        Remove sensitivity label from a file.

        Args:
            file_path: Path to the file

        Returns:
            LabelingResult indicating success/failure
        """
        if not self._initialized:
            return LabelingResult(
                success=False,
                file_path=file_path,
                error="MIP client not initialized",
            )

        if not Path(file_path).exists():
            return LabelingResult(
                success=False,
                file_path=file_path,
                error="File not found",
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                partial(self._remove_label_sync, file_path)
            )
            return result

        except Exception as e:
            logger.error(f"Failed to remove label from {file_path}: {e}")
            return LabelingResult(
                success=False,
                file_path=file_path,
                error=str(e),
            )

    def _remove_label_sync(self, file_path: str) -> LabelingResult:
        """Synchronous label removal."""
        from Microsoft.InformationProtection.File import FileHandler
        from Microsoft.InformationProtection import ActionSource

        handler = None
        try:
            # Create file handler
            handler = self._file_engine.CreateFileHandler(
                file_path,
                self._create_file_observer(),
            )

            # Get current label info
            current_label = handler.Label
            was_protected = handler.Protection is not None if hasattr(handler, 'Protection') else False

            if not current_label:
                return LabelingResult(
                    success=True,
                    file_path=file_path,
                    error="No label to remove",
                )

            # Remove the label
            handler.DeleteLabel(ActionSource.Manual)

            # Commit changes
            committed = handler.CommitAsync(file_path).GetAwaiter().GetResult()

            if committed:
                return LabelingResult(
                    success=True,
                    file_path=file_path,
                    was_protected=was_protected,
                    is_protected=False,
                )
            else:
                return LabelingResult(
                    success=False,
                    file_path=file_path,
                    error="Commit returned false",
                )

        except Exception as e:
            return LabelingResult(
                success=False,
                file_path=file_path,
                error=str(e),
            )
        finally:
            if handler:
                try:
                    handler.Dispose()
                except Exception:
                    pass

    async def get_file_label(self, file_path: str) -> Optional[SensitivityLabel]:
        """
        Get the current label on a file.

        Args:
            file_path: Path to the file

        Returns:
            Current label if any, None otherwise
        """
        if not self._initialized:
            return None

        if not Path(file_path).exists():
            return None

        try:
            loop = asyncio.get_event_loop()
            label = await loop.run_in_executor(
                None,
                partial(self._get_file_label_sync, file_path)
            )
            return label

        except Exception as e:
            logger.error(f"Failed to get label from {file_path}: {e}")
            return None

    def _get_file_label_sync(self, file_path: str) -> Optional[SensitivityLabel]:
        """Synchronous label reading."""
        handler = None
        try:
            handler = self._file_engine.CreateFileHandler(
                file_path,
                self._create_file_observer(),
            )

            content_label = handler.Label
            if not content_label or not content_label.Label:
                return None

            mip_label = content_label.Label
            return SensitivityLabel(
                id=mip_label.Id,
                name=mip_label.Name,
                description=mip_label.Description or "",
                tooltip=mip_label.Tooltip or "",
                color=mip_label.Color if hasattr(mip_label, 'Color') else None,
                priority=mip_label.Priority if hasattr(mip_label, 'Priority') else 0,
                parent_id=mip_label.Parent.Id if mip_label.Parent else None,
                is_active=mip_label.IsActive if hasattr(mip_label, 'IsActive') else True,
            )

        except Exception as e:
            logger.error(f"Failed to read label: {e}")
            return None
        finally:
            if handler:
                try:
                    handler.Dispose()
                except Exception:
                    pass

    async def is_file_protected(self, file_path: str) -> bool:
        """
        Check if a file is protected (encrypted) with MIP.

        Args:
            file_path: Path to the file

        Returns:
            True if file is protected
        """
        if not self._initialized or not Path(file_path).exists():
            return False

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                partial(self._is_file_protected_sync, file_path)
            )
            return result

        except Exception:
            return False

    def _is_file_protected_sync(self, file_path: str) -> bool:
        """Synchronous protection check."""
        handler = None
        try:
            handler = self._file_engine.CreateFileHandler(
                file_path,
                self._create_file_observer(),
            )
            return handler.Protection is not None if hasattr(handler, 'Protection') else False

        except Exception:
            return False
        finally:
            if handler:
                try:
                    handler.Dispose()
                except Exception:
                    pass


def is_mip_available() -> bool:
    """Check if MIP SDK is available."""
    return PYTHONNET_AVAILABLE
