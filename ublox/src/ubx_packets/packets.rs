use super::{
    ubx_checksum, MemWriter, Position, UbxChecksumCalc, UbxPacketCreator, UbxPacketMeta,
    UbxUnknownPacketRef, SYNC_CHAR_1, SYNC_CHAR_2,
};
use crate::error::{MemWriterError, ParserError};
use bitflags::bitflags;
use chrono::prelude::*;
use core::fmt;
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_traits::float::FloatCore;
use ublox_derive::{
    define_recv_packets, ubx_extend, ubx_extend_bitflags, ubx_packet_recv, ubx_packet_recv_send,
    ubx_packet_send,
};

use serde_derive::{Serialize, Deserialize};

//use rinex::constellation::{Constellation, Augmentation};

/*
macro_rules! sbas_supported {
    ($sbas: expr) => {
        $sbas in vec![
            Augmentation::WAAS,
            Augmentation::EGNOS,
            Augmentation::MSAS,
            Augmentation::GAGAN,
        ]
    }
}*/

/// Geodetic Position Solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 2, fixed_payload_len = 28)]
struct NavPosLlh {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// Longitude
    #[ubx(map_type = f64, scale = 1e-7, alias = lon_degrees)]
    lon: i32,

    /// Latitude
    #[ubx(map_type = f64, scale = 1e-7, alias = lat_degrees)]
    lat: i32,

    /// Height above Ellipsoid
    #[ubx(map_type = f64, scale = 1e-3)]
    height_meters: i32,

    /// Height above mean sea level
    #[ubx(map_type = f64, scale = 1e-3)]
    height_msl: i32,

    /// Horizontal Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-3)]
    h_ack: u32,

    /// Vertical Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-3)]
    v_acc: u32,
}

/// NAV Survey 
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x3B, fixed_payload_len = 40)]
struct NavSvin {
    version: u8,
    reserved1: [u8; 3],
    itow: u32,
    duration: u32,
    #[ubx(map_type = f64, scale = 1e-2)]
    mean_x: i32,
    #[ubx(map_type = f64, scale = 1e-2)]
    mean_y: i32,
    #[ubx(map_type = f64, scale = 1e-2)]
    mean_z: i32,
    #[ubx(map_type = f64, scale = 0.1e-3)]
    mean_x_hp: i8,
    #[ubx(map_type = f64, scale = 0.1e-3)]
    mean_y_hp: i8,
    #[ubx(map_type = f64, scale = 0.1e-3)]
    mean_z_hp: i8,
    reserved2: u8,
    #[ubx(map_type = f64, scale = 0.1e-3)]
    mean_acc: u32,
    obs: u32,
    valid: u8,
    active: u8,
    reserved3: [u8; 2],
}

/// Velocity Solution in NED
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x12, fixed_payload_len = 36)]
struct NavVelNed {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// north velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    vel_north: i32,

    /// east velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    vel_east: i32,

    /// down velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    vel_down: i32,

    /// Speed 3-D (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    speed_3d: u32,

    /// Ground speed (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ground_speed: u32,

    /// Heading of motion 2-D (degrees)
    #[ubx(map_type = f64, scale = 1e-5, alias = heading_degrees)]
    heading: i32,

    /// Speed Accuracy Estimate (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    speed_accuracy_estimate: u32,

    /// Course / Heading Accuracy Estimate (degrees)
    #[ubx(map_type = f64, scale = 1e-5)]
    course_heading_accuracy_estimate: u32,
}

/// Navigation Position Velocity Time Solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x07, fixed_payload_len = 92)]
struct NavPosVelTime {
    /// GPS Millisecond Time of Week
    itow: u32,
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    min: u8,
    sec: u8,
    valid: u8,
    time_accuracy: u32,
    nanosecond: i32,

    /// GNSS fix Type
    #[ubx(map_type = GpsFix)]
    fix_type: u8,
    #[ubx(map_type = NavPosVelTimeFlags)]
    flags: u8,
    #[ubx(map_type = NavPosVelTimeFlags2)]
    flags2: u8,
    num_satellites: u8,
    #[ubx(map_type = f64, scale = 1e-7, alias = lon_degrees)]
    lon: i32,
    #[ubx(map_type = f64, scale = 1e-7, alias = lat_degrees)]
    lat: i32,

    /// Height above Ellipsoid
    #[ubx(map_type = f64, scale = 1e-3)]
    height_meters: i32,

    /// Height above mean sea level
    #[ubx(map_type = f64, scale = 1e-3)]
    height_msl: i32,
    horiz_accuracy: u32,
    vert_accuracy: u32,

    /// north velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    vel_north: i32,

    /// east velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    vel_east: i32,

    /// down velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    vel_down: i32,

    /// Ground speed (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    ground_speed: u32,

    /// Heading of motion 2-D (degrees)
    #[ubx(map_type = f64, scale = 1e-5, alias = heading_degrees)]
    heading: i32,

    /// Speed Accuracy Estimate (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    speed_accuracy_estimate: u32,

    /// Heading accuracy estimate (both motionand vehicle) (degrees)
    #[ubx(map_type = f64, scale = 1e-5)]
    heading_accuracy_estimate: u32,

    /// Position DOP
    pdop: u16,
    reserved1: [u8; 6],
    #[ubx(map_type = f64, scale = 1e-5, alias = heading_of_vehicle_degrees)]
    heading_of_vehicle: i32,
    #[ubx(map_type = f64, scale = 1e-2, alias = magnetic_declination_degrees)]
    magnetic_declination: i16,
    #[ubx(map_type = f64, scale = 1e-2, alias = magnetic_declination_accuracy_degrees)]
    magnetic_declination_accuracy: u16,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Fix status flags for `NavPosVelTime`
    pub struct NavPosVelTimeFlags: u8 {
        /// position and velocity valid and within DOP and ACC Masks
        const GPS_FIX_OK = 1;
        /// DGPS used
        const DIFF_SOLN = 2;
        /// 1 = heading of vehicle is valid
        const HEAD_VEH_VALID = 0x20;
        const CARR_SOLN_FLOAT = 0x40;
        const CARR_SOLN_FIXED = 0x80;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Additional flags for `NavPosVelTime`
    pub struct NavPosVelTimeFlags2: u8 {
        /// 1 = information about UTC Date and Time of Day validity confirmation
        /// is available. This flag is only supported in Protocol Versions
        /// 19.00, 19.10, 20.10, 20.20, 20.30, 22.00, 23.00, 23.01,27 and 28.
        const CONFIRMED_AVAI = 0x20;
        /// 1 = UTC Date validity could be confirmed
        /// (confirmed by using an additional independent source)
        const CONFIRMED_DATE = 0x40;
        /// 1 = UTC Time of Day could be confirmed
        /// (confirmed by using an additional independent source)
        const CONFIRMED_TIME = 0x80;
    }
}

///  Receiver Navigation Status
#[ubx_packet_recv]
#[ubx(class = 1, id = 3, fixed_payload_len = 16)]
struct NavStatus {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// GPS fix Type, this value does not qualify a fix as

    /// valid and within the limits
    #[ubx(map_type = GpsFix)]
    fix_type: u8,

    /// Navigation Status Flags
    #[ubx(map_type = NavStatusFlags)]
    flags: u8,

    /// Fix Status Information
    #[ubx(map_type = FixStatusInfo)]
    fix_stat: u8,

    /// further information about navigation output
    #[ubx(map_type = NavStatusFlags2)]
    flags2: u8,

    /// Time to first fix (millisecond time tag)
    time_to_first_fix: u32,

    /// Milliseconds since Startup / Reset
    uptime_ms: u32,
}

/// Dilution of precision
#[ubx_packet_recv]
#[ubx(class = 1, id = 4, fixed_payload_len = 18)]
struct NavDop {
    /// GPS Millisecond Time of Week
    itow: u32,
    #[ubx(map_type = f32, scale = 1e-2)]
    geometric_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    position_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    time_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    vertical_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    horizontal_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    northing_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    easting_dop: u16,
}

/// Navigation Solution Information
#[ubx_packet_recv]
#[ubx(class = 1, id = 6, fixed_payload_len = 52)]
struct NavSolution {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// Fractional part of iTOW (range: +/-500000).
    ftow_ns: i32,

    /// GPS week number of the navigation epoch
    week: i16,

    /// GPS fix Type
    #[ubx(map_type = GpsFix)]
    fix_type: u8,

    /// Navigation Status Flags
    #[ubx(map_type = NavStatusFlags)]
    flags: u8,

    /// ECEF X coordinate (meters)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_x: i32,

    /// ECEF Y coordinate (meters)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_y: i32,

    /// ECEF Z coordinate (meters)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_z: i32,

    /// 3D Position Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-2)]
    position_accuracy_estimate: u32,

    /// ECEF X velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_vx: i32,

    /// ECEF Y velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_vy: i32,

    /// ECEF Z velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_vz: i32,

    /// Speed Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-2)]
    speed_accuracy_estimate: u32,

    /// Position DOP
    #[ubx(map_type = f32, scale = 1e-2)]
    pdop: u16,
    reserved1: u8,

    /// Number of SVs used in Nav Solution
    num_sv: u8,
    reserved2: [u8; 4],
}

/// GPS fix Type
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum GpsFix {
    NoFix = 0,
    DeadReckoningOnly = 1,
    Fix2D = 2,
    Fix3D = 3,
    GPSPlusDeadReckoning = 4,
    TimeOnlyFix = 5,
}

impl Default for GpsFix {
    fn default() -> Self {
        Self::NoFix
    }
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Navigation Status Flags
    #[derive(Default)]
    pub struct NavStatusFlags: u8 {
        /// position and velocity valid and within DOP and ACC Masks
        const GPS_FIX_OK = 1;
        /// DGPS used
        const DIFF_SOLN = 2;
        /// Week Number valid
        const WKN_SET = 4;
        /// Time of Week valid
        const TOW_SET = 8;
    }
}

/// Fix Status Information
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct FixStatusInfo(u8);

impl FixStatusInfo {
    pub const fn has_pr_prr_correction(self) -> bool {
        (self.0 & 1) == 1
    }
    pub fn map_matching(self) -> MapMatchingStatus {
        let bits = (self.0 >> 6) & 3;
        match bits {
            0 => MapMatchingStatus::None,
            1 => MapMatchingStatus::Valid,
            2 => MapMatchingStatus::Used,
            3 => MapMatchingStatus::Dr,
            _ => unreachable!(),
        }
    }
    pub const fn from(x: u8) -> Self {
        Self(x)
    }
}

impl fmt::Debug for FixStatusInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixStatusInfo")
            .field("has_pr_prr_correction", &self.has_pr_prr_correction())
            .field("map_matching", &self.map_matching())
            .finish()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum MapMatchingStatus {
    None = 0,
    /// valid, i.e. map matching data was received, but was too old
    Valid = 1,
    /// used, map matching data was applied
    Used = 2,
    /// map matching was the reason to enable the dead reckoning
    /// gpsFix type instead of publishing no fix
    Dr = 3,
}

/// Further information about navigation output
/// Only for FW version >= 7.01; undefined otherwise
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
enum NavStatusFlags2 {
    Acquisition = 0,
    Tracking = 1,
    PowerOptimizedTracking = 2,
    Inactive = 3,
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct NavSatSvFlags(u32);

impl NavSatSvFlags {
    pub fn quality_ind(self) -> NavSatQualityIndicator {
        let bits = self.0 & 0x7;
        match bits {
            0 => NavSatQualityIndicator::NoSignal,
            1 => NavSatQualityIndicator::Searching,
            2 => NavSatQualityIndicator::SignalAcquired,
            3 => NavSatQualityIndicator::SignalDetected,
            4 => NavSatQualityIndicator::CodeLock,
            5 | 6 | 7 => NavSatQualityIndicator::CarrierLock,
            _ => {
                panic!("Unexpected 3-bit bitfield value {}!", bits);
            }
        }
    }

    pub fn sv_used(self) -> bool {
        (self.0 >> 3) & 0x1 != 0
    }

    pub fn health(self) -> NavSatSvHealth {
        let bits = (self.0 >> 4) & 0x3;
        match bits {
            1 => NavSatSvHealth::Healthy,
            2 => NavSatSvHealth::Unhealthy,
            x => NavSatSvHealth::Unknown(x as u8),
        }
    }

    pub fn differential_correction_available(self) -> bool {
        (self.0 >> 6) & 0x1 != 0
    }

    pub fn smoothed(self) -> bool {
        (self.0 >> 7) & 0x1 != 0
    }

    pub fn orbit_source(self) -> NavSatOrbitSource {
        let bits = (self.0 >> 8) & 0x7;
        match bits {
            0 => NavSatOrbitSource::NoInfoAvailable,
            1 => NavSatOrbitSource::Ephemeris,
            2 => NavSatOrbitSource::Almanac,
            3 => NavSatOrbitSource::AssistNowOffline,
            4 => NavSatOrbitSource::AssistNowAutonomous,
            x => NavSatOrbitSource::Other(x as u8),
        }
    }

    pub fn ephemeris_available(self) -> bool {
        (self.0 >> 11) & 0x1 != 0
    }

    pub fn almanac_available(self) -> bool {
        (self.0 >> 12) & 0x1 != 0
    }

    pub fn an_offline_available(self) -> bool {
        (self.0 >> 13) & 0x1 != 0
    }

    pub fn an_auto_available(self) -> bool {
        (self.0 >> 14) & 0x1 != 0
    }

    pub fn sbas_corr(self) -> bool {
        (self.0 >> 16) & 0x1 != 0
    }

    pub fn rtcm_corr(self) -> bool {
        (self.0 >> 17) & 0x1 != 0
    }

    pub fn slas_corr(self) -> bool {
        (self.0 >> 18) & 0x1 != 0
    }

    pub fn spartn_corr(self) -> bool {
        (self.0 >> 19) & 0x1 != 0
    }

    pub fn pr_corr(self) -> bool {
        (self.0 >> 20) & 0x1 != 0
    }

    pub fn cr_corr(self) -> bool {
        (self.0 >> 21) & 0x1 != 0
    }

    pub fn do_corr(self) -> bool {
        (self.0 >> 22) & 0x1 != 0
    }

    pub const fn from(x: u32) -> Self {
        Self(x)
    }
}

impl fmt::Debug for NavSatSvFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NavSatSvFlags")
            .field("quality_ind", &self.quality_ind())
            .field("sv_used", &self.sv_used())
            .field("health", &self.health())
            .field(
                "differential_correction_available",
                &self.differential_correction_available(),
            )
            .field("smoothed", &self.smoothed())
            .field("orbit_source", &self.orbit_source())
            .field("ephemeris_available", &self.ephemeris_available())
            .field("almanac_available", &self.almanac_available())
            .field("an_offline_available", &self.an_offline_available())
            .field("an_auto_available", &self.an_auto_available())
            .field("sbas_corr", &self.sbas_corr())
            .field("rtcm_corr", &self.rtcm_corr())
            .field("slas_corr", &self.slas_corr())
            .field("spartn_corr", &self.spartn_corr())
            .field("pr_corr", &self.pr_corr())
            .field("cr_corr", &self.cr_corr())
            .field("do_corr", &self.do_corr())
            .finish()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum NavSatQualityIndicator {
    NoSignal,
    Searching,
    SignalAcquired,
    SignalDetected,
    CodeLock,
    CarrierLock,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum NavSatSvHealth {
    Healthy,
    Unhealthy,
    Unknown(u8),
}

impl Default for NavSatSvHealth {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum NavSatOrbitSource {
    NoInfoAvailable,
    Ephemeris,
    Almanac,
    AssistNowOffline,
    AssistNowAutonomous,
    Other(u8),
}

#[ubx_packet_recv]
#[ubx(class = 0x01, id = 0x35, fixed_payload_len = 12)]
struct NavSatSvInfo {
    gnss_id: u8,
    sv_id: u8,
    cno: u8,
    elev: i8,
    azim: i16,
    pr_res: i16,
    #[ubx(map_type = NavSatSvFlags)]
    flags: u32,
}

/*impl fmt::Debug for NavSatSvInfoRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NavSatSvInfo")
            .field("gnss_id", &self.gnss_id())
            .field("sv_id", &self.sv_id())
            .field("cno", &self.cno())
            .field("elev", &self.elev())
            .field("azim", &self.azim())
            .field("pr_res", &self.pr_res())
            .field("flags", &self.flags())
            .finish()
    }
}*/

pub struct NavSatIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> core::iter::Iterator for NavSatIter<'a> {
    type Item = NavSatSvInfoRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < self.data.len() {
            let data = &self.data[self.offset..self.offset + 12];
            self.offset += 12;
            Some(NavSatSvInfoRef(data))
        } else {
            None
        }
    }
}

impl fmt::Debug for NavSatIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NavSatIter").finish()
    }
}

#[ubx_packet_recv]
#[ubx(class = 0x01, id = 0x35, max_payload_len = 1240)]
struct NavSat {
    /// GPS time of week in ms
    itow: u32,

    /// Message version, should be 1
    version: u8,

    num_svs: u8,

    reserved: u16,

    #[ubx(map_type = NavSatIter,
        may_fail,
        is_valid = navsat::is_valid,
        from = navsat::convert_to_iter,
        get_as_ref,
    )]
    svs: [u8; 0],
}

mod navsat {
    use super::NavSatIter;

    pub(crate) fn convert_to_iter(bytes: &[u8]) -> NavSatIter {
        NavSatIter {
            data: bytes,
            offset: 0,
        }
    }

    pub(crate) fn is_valid(bytes: &[u8]) -> bool {
        bytes.len() % 12 == 0
    }
}

/// Odometer solution
#[ubx_packet_recv]
#[ubx(class = 0x01, id = 0x09, fixed_payload_len = 20)]
struct NavOdo {
    version: u8,
    reserved: [u8; 3],
    i_tow: u32,
    distance: u32,
    total_distance: u32,
    distance_std: u32,
}

/// Reset odometer
#[ubx_packet_send]
#[ubx(class = 0x01, id = 0x10, fixed_payload_len = 0)]
struct NavResetOdo {}

/// End of Epoch Marker
#[ubx_packet_recv]
#[ubx(class = 0x01, id = 0x61, fixed_payload_len = 4)]
struct NavEoe {
    /// GPS time of week for navigation epoch
    itow: u32,
}

/// Sends "Stop calibration" request
#[ubx_packet_send]
#[ubx(class = 0x01, id = 0x01, fixed_payload_len = 0)]
struct TimVcoStopCal {}
//    /// 0x00 for this message
//    msg_type: u8,
//}

/*
/// Local OSC calibration management frame
#[ubx_packet_send]
#[ubx(
    class = 0x0D,
    id = 0x15,
    fixed_payload_len = 12
)]
struct TimVcoCal2 {
    msg_type: u8,
    version: u8,
    osc_id: u8,
    src_id: u8,
    reserved1: [u8; 2],
    raw0: u16,
    raw1: u16,
    max_step_size: u16,
}

/// Local OSC calibration results
#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x15,
    fixed_payload_len = 12
)]
struct TimVcoCal3 {
    msg_type: u8,
    version: u8,
    osc_id: u8,
    reserved1: [u8; 3],
    gain_uncertainty: u16,
    gain_vco: i32,
}*/

/*
/// Differential GNSS configuration frame (32.10.5)
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x70,
    fixed_payload_len = 4,
    flags = "default_for_builder"
)]
struct CfgDgnss {
    /// Specificies differential mode, refer to [CfgDnssModes]
    #[ubx(map_type = CfgDgnssModes, may_fail)]
    dgnss_mode: u8,
    reserved: [u8; 3],
}

/// Differential GNSS mode
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
enum CfgDgnssModes {
    /// No attempts are made to fix ambiguities
    RtkFloat = 2,
    /// Ambiguities are fixed whenever possible
    RtkFixed = 3,
}

impl Default for CfgDgnssModes {
    fn default() -> CfgDgnssModes {
        CfgDgnssModes::RtkFloat
    }
}*/

/// Configure odometer
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x1E,
    fixed_payload_len = 20,
    flags = "default_for_builder"
)]
struct CfgOdo {
    version: u8,
    reserved: [u8; 3],
    /// Odometer COG filter flags. See [OdoCogFilterFlags] for details.
    #[ubx(map_type = OdoCogFilterFlags)]
    flags: u8,
    #[ubx(map_type = OdoProfile, may_fail)]
    odo_cfg: u8,
    reserved2: [u8; 6],
    cog_max_speed: u8,
    cog_max_pos_acc: u8,
    reserved3: [u8; 2],
    vel_lp_gain: u8,
    cog_lp_gain: u8,
    reserved4: [u8; 2],
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct OdoCogFilterFlags: u8 {
        /// Odometer enabled flag
        const USE_ODO = 0x01;
        /// Low-speed COG filter enabled flag
        const USE_COG = 0x02;
        /// Output low-pass filtered velocity flag
        const OUT_LP_VEL = 0x04;
        /// Output low-pass filtered heading (COG) flag
        const OUT_LP_COG = 0x08;
    }
}

/// Odometer configuration profile
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum OdoProfile {
    Running = 0,
    Cycling = 1,
    Swimming = 2,
    Car = 3,
    Custom = 4,
}

impl Default for OdoProfile {
    fn default() -> Self {
        Self::Running
    }
}

/// Information message conifg
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x2,
    fixed_payload_len = 10,
    flags = "default_for_builder"
)]
struct CfgInf {
    protocol_id: u8,
    reserved: [u8; 3],
    #[ubx(map_type = CfgInfMask)]
    inf_msg_mask_0: u8,
    #[ubx(map_type = CfgInfMask)]
    inf_msg_mask_1: u8,
    #[ubx(map_type = CfgInfMask)]
    inf_msg_mask_2: u8,
    #[ubx(map_type = CfgInfMask)]
    inf_msg_mask_3: u8,
    #[ubx(map_type = CfgInfMask)]
    inf_msg_mask_4: u8,
    #[ubx(map_type = CfgInfMask)]
    inf_msg_mask_5: u8,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// `CfgInfMask` parameters bitmask
    #[derive(Default)]
    pub struct CfgInfMask: u8 {
        const ERROR = 0x1;
        const WARNING = 0x2;
        const NOTICE = 0x4;
        const DEBUG = 0x08;
        const TEST  = 0x10;
    }
}

#[ubx_packet_recv]
#[ubx(
    class = 0x4,
    id = 0x0,
    max_payload_len = 1240,
    flags = "default_for_builder"
)]
struct InfError {
    #[ubx(map_type = Option<&str>,
        may_fail,
        is_valid = inf::is_valid,
        from = inf::convert_to_str,
        get_as_ref)]
    message: [u8; 0],
}

#[ubx_packet_recv]
#[ubx(
    class = 0x4,
    id = 0x2,
    max_payload_len = 1240,
    flags = "default_for_builder"
)]
struct InfNotice {
    #[ubx(map_type = Option<&str>,
        may_fail,
        is_valid = inf::is_valid,
        from = inf::convert_to_str,
        get_as_ref)]
    message: [u8; 0],
}

#[ubx_packet_recv]
#[ubx(
    class = 0x4,
    id = 0x3,
    max_payload_len = 1240,
    flags = "default_for_builder"
)]
struct InfTest {
    #[ubx(map_type = Option<&str>,
        may_fail,
        is_valid = inf::is_valid,
        from = inf::convert_to_str,
        get_as_ref)]
    message: [u8; 0],
}

#[ubx_packet_recv]
#[ubx(
    class = 0x4,
    id = 0x1,
    max_payload_len = 1240,
    flags = "default_for_builder"
)]
struct InfWarning {
    #[ubx(map_type = Option<&str>,
        may_fail,
        is_valid = inf::is_valid,
        from = inf::convert_to_str,
        get_as_ref)]
    message: [u8; 0],
}

#[ubx_packet_recv]
#[ubx(
    class = 0x4,
    id = 0x4,
    max_payload_len = 1240,
    flags = "default_for_builder"
)]
struct InfDebug {
    #[ubx(map_type = Option<&str>,
        may_fail,
        is_valid = inf::is_valid,
        from = inf::convert_to_str,
        get_as_ref)]
    message: [u8; 0],
}

mod inf {
    pub(crate) fn convert_to_str(bytes: &[u8]) -> Option<&str> {
        match core::str::from_utf8(bytes) {
            Ok(msg) => Some(msg),
            Err(_) => None,
        }
    }

    pub(crate) fn is_valid(_bytes: &[u8]) -> bool {
        // Validity is checked in convert_to_str
        true
    }
}

#[ubx_packet_send]
#[ubx(
    class = 0x0B,
    id = 0x01,
    fixed_payload_len = 48,
    flags = "default_for_builder"
)]
struct AidIni {
    ecef_x_or_lat: i32,
    ecef_y_or_lon: i32,
    ecef_z_or_alt: i32,
    pos_accuracy: u32,
    time_cfg: u16,
    week_or_ym: u16,
    tow_or_hms: u32,
    tow_ns: i32,
    tm_accuracy_ms: u32,
    tm_accuracy_ns: u32,
    clk_drift_or_freq: i32,
    clk_drift_or_freq_accuracy: u32,
    flags: u32,
}

impl AidIniBuilder {
    pub fn set_position(mut self, pos: Position) -> Self {
        self.ecef_x_or_lat = (pos.lat * 10_000_000.0) as i32;
        self.ecef_y_or_lon = (pos.lon * 10_000_000.0) as i32;
        self.ecef_z_or_alt = (pos.alt * 100.0) as i32; // Height is in centimeters, here
        self.flags |= (1 << 0) | (1 << 5);
        self
    }

    pub fn set_time(mut self, tm: DateTime<Utc>) -> Self {
        self.week_or_ym = (match tm.year_ce() {
            (true, yr) => yr - 2000,
            (false, _) => {
                panic!("AID-INI packet only supports years after 2000");
            }
        } * 100
            + tm.month0()) as u16;
        self.tow_or_hms = tm.hour() * 10000 + tm.minute() * 100 + tm.second();
        self.tow_ns = tm.nanosecond() as i32;
        self.flags |= (1 << 1) | (1 << 10);
        self
    }
}

/// ALP client requests AlmanacPlus data from server
#[ubx_packet_recv]
#[ubx(class = 0x0B, id = 0x32, fixed_payload_len = 16)]
struct AlpSrv {
    pub id_size: u8,
    pub data_type: u8,
    pub offset: u16,
    pub size: u16,
    pub file_id: u16,
    pub data_size: u16,
    pub id1: u8,
    pub id2: u8,
    pub id3: u32,
}

/// Messages in this class are sent as a result of a CFG message being
/// received, decoded and processed by thereceiver.
#[ubx_packet_recv]
#[ubx(class = 5, id = 1, fixed_payload_len = 2)]
struct AckAck {
    /// Class ID of the Acknowledged Message
    class: u8,

    /// Message ID of the Acknowledged Message
    msg_id: u8,
}

impl<'a> AckAckRef<'a> {
    pub fn is_ack_for<T: UbxPacketMeta>(&self) -> bool {
        self.class() == T::CLASS && self.msg_id() == T::ID
    }
}

/// Message Not-Acknowledge
#[ubx_packet_recv]
#[ubx(class = 5, id = 0, fixed_payload_len = 2)]
struct AckNak {
    /// Class ID of the Acknowledged Message
    class: u8,

    /// Message ID of the Acknowledged Message
    msg_id: u8,
}

impl<'a> AckNakRef<'a> {
    pub fn is_nak_for<T: UbxPacketMeta>(&self) -> bool {
        self.class() == T::CLASS && self.msg_id() == T::ID
    }
}

/// Reset Receiver / Clear Backup Data Structures
#[ubx_packet_send]
#[ubx(
    class = 6, 
    id = 4, 
    fixed_payload_len = 4
)]
struct CfgRst {
    /// Battery backed RAM sections to clear
    #[ubx(map_type = NavBbrMask)]
    nav_bbr_mask: u16,
    /// Reset Type
    #[ubx(map_type = ResetMode)]
    reset_mode: u8,
    reserved1: u8,
}

impl ResetMode {
    const fn into_raw(self) -> u8 {
        self as u8
    }
}

/// GNSS System Configuration frame
#[ubx_packet_recv_send]
//#[ubx_packet_send]
#[ubx(
    class = 0x06, 
    id = 0x3E,
    fixed_payload_len = 60,
)]
struct CfgGnss {
    /// Version: 0 for this version
    version: u8,
    /// Number of tracking channels available
    /// (hardware dependent), read only information
    num_trk_ch_hw: u8,
    /// Number of tracking channels to use
    num_trk_ch_use: u8,
    /// Number of configuration blocks
    num_cfg: u8,
    /// GPS_ID = 0
    gps_id: u8,
    gps_res_trk_ch: u8,
    gps_max_trk_ch: u8,
    gps_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    gps_flags: u32, 
    /// SBAS_ID = 1
    sbas_id: u8,
    sbas_res_trk_ch: u8,
    sbas_max_trk_ch: u8,
    sbas_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    sbas_flags: u32, 
    /// GAL_ID = 2
    gal_id: u8,
    gal_res_trk_ch: u8,
    gal_max_trk_ch: u8,
    gal_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    gal_flags: u32, 
    /// BDS_ID = 3
    bds_id: u8,
    bds_res_trk_ch: u8,
    bds_max_trk_ch: u8,
    bds_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    bds_flags: u32, 
    /// IMES_ID = 4
    imes_id: u8,
    imes_res_trk_ch: u8,
    imes_max_trk_ch: u8,
    imes_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    imes_flags: u32, 
    /// QZSS_ID = 5
    qzss_id: u8,
    qzss_res_trk_ch: u8,
    qzss_max_trk_ch: u8,
    qzss_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    qzss_flags: u32, 
    /// GLO_ID = 6
    glo_id: u8,
    glo_res_trk_ch: u8,
    glo_max_trk_ch: u8,
    glo_reserved1: u8,
    #[ubx(map_type = CfgGnssFlags)]
    glo_flags: u32, 
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    #[derive(Serialize, Deserialize)]
    pub struct CfgGnssFlags: u32 {
        /// Enable this system
        const ENABLE = 0x01;
        /// systems
        const L1  = 0x010000;
        const L1S = 0x040000;
        const L2 =  0x100000;
        const L5 =  0x200000;
        const B2A = 0x800000;
    }
}

#[ubx_packet_recv_send]
#[ubx(
    class = 0x06, 
    id = 0x3E, 
    fixed_payload_len = 4,
    flags = "default_for_builder",
)]
struct CfgGnssItem {
    gnss_id: u8,
    res_trk_ch: u8,
    max_trk_ch: u8,
    reserved1: u8,
}

pub struct CfgGnssIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> core::iter::Iterator for CfgGnssIter<'a> {
    type Item = CfgGnssItemRef<'a>;
    
    fn next (&mut self) -> Option<Self::Item> {
        if self.offset < self.data.len() {
            let data = &self.data[self.offset..self.offset +8];
            self.offset += 8;
            Some(CfgGnssItemRef(data))
        } else {
            None
        }
    }
}

impl fmt::Debug for CfgGnssIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CfgGnssIter").finish()
    }
}

mod cfggnss {
    use super::CfgGnssIter;
    
    pub(crate) fn is_valid (bytes: &[u8]) -> bool {
        bytes.len() % 8  == 0
    }

    pub(crate) fn convert_to_iter (bytes: &[u8]) -> CfgGnssIter {
        CfgGnssIter {
            data: bytes,
            offset: 0,
        }
    }
}

/// Reset Receiver / Clear Backup Data Structures
#[ubx_packet_recv_send]
#[ubx(
    class = 6, 
    id = 0x13, 
    fixed_payload_len = 4,
    flags = "default_for_builder",
)]
struct CfgAnt {
    /// Antenna flag mask. See [AntFlags] for details.
    #[ubx(map_type = AntFlags)]
    flags: u16,
    /// Antenna pin configuration. See 32.10.1.1 in receiver spec for details.
    pins: u16,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct AntFlags: u16 {
        /// Enable supply voltage control signal
        const SVCS = 0x01;
        /// Enable short circuit detection
        const SCD = 0x02;
        /// Enable open circuit detection
        const OCD = 0x04;
        /// Power down on short circuit detection
        const PDWN_ON_SCD = 0x08;
        /// Enable automatic recovery from short circuit state
        const RECOVERY = 0x10;
    }
}

/// Time MODE2 Config Frame (32.10.36.1)
/// only available on `timing` receivers
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06, 
    id = 0x3d, 
    fixed_payload_len = 28, 
    flags = "default_for_builder"
)]
struct CfgTmode2 {
    /// Time transfer modes, see [CfgTmode2TimeXferModes] for details
    #[ubx(map_type = CfgTmode2TimeXferModes, may_fail)]
    time_transfer_mode: u8,
    reserved1: u8,
    #[ubx(map_type = CfgTmode2Flags)] 
    flags: u16,
    /// WGS84 ECEF.x coordinate in [m] or latitude in [deg° *1E-5],
    /// depending on `flags` field 
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_x_or_lat: i32,
    /// WGS84 ECEF.y coordinate in [m] or longitude in [deg° *1E-5],
    /// depending on `flags` field 
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_y_or_lon: i32,
    /// WGS84 ECEF.z coordinate or altitude, both in [m],
    /// depending on `flags` field 
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_z_or_alt: i32,
    /// Fixed position 3D accuracy in [m]
    #[ubx(map_type = f64, scale = 1e-3)]
    fixed_pos_acc: u32,
    /// Survey in minimum duration in [s]
    survey_in_min_duration: u32,
    /// Survey in position accuracy limit in [m]
    #[ubx(map_type = f64, scale = 1e-3)]
    survery_in_accur_limit: u32,
}

/// Time transfer modes (32.10.36)
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CfgTmode2TimeXferModes {
    Disabled = 0,
    SurveyIn = 1,
    /// True position information required
    /// when using `fixed mode`
    FixedMode = 2,
}

impl Default for CfgTmode2TimeXferModes {
    fn default() -> Self {
        Self::Disabled
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct CfgTmode2Flags :u16 {
        /// Position given in LAT/LON/ALT
        /// default being WGS84 ECEF
        const LLA = 0x01;
        /// In case LLA was set, Altitude value is not valid
        const ALT_INVALID = 0x02;
    }
}

/// Time MODE3 Config Frame (32.10.37.1)
/// only available on `timing` receivers
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06, 
    id = 0x71, 
    fixed_payload_len = 40,
    flags = "default_for_builder"
)] 
struct CfgTmode3 {
    version: u8,
    reserved1: u8,
    /// Receiver mode, see [CfgTmode3RcvrMode] enum
    #[ubx(map_type = CfgTmode3RcvrMode)]
    rcvr_mode: u8,
    #[ubx(map_type = CfgTmode3Flags)] 
    flags: u8,
    /// WGS84 ECEF.x coordinate in [m] or latitude in [deg° *1E-5],
    /// depending on `flags` field 
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_x_or_lat: i32,
    /// WGS84 ECEF.y coordinate in [m] or longitude in [deg° *1E-5],
    /// depending on `flags` field 
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_y_or_lon: i32,
    /// WGS84 ECEF.z coordinate or altitude, both in [m], 
    /// depending on `flags` field 
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_z_or_alt: i32,
    /// High precision WGS84 ECEF.x coordinate in [tenths of mm],
    /// or high precision latitude, in nano degrees,
    /// depending on `flags` field.
    #[ubx(map_type = f32, scale = 1.0)]
    ecef_x_or_lat_hp: i8,
    /// High precision WGS84 ECEF.y coordinate in [tenths of mm]
    /// or high precision longitude, in nano degrees,
    /// depending on `flags` field.
    #[ubx(map_type = f32, scale = 1.0)]
    ecef_y_or_lon_hp: i8,
    /// High precision WGS84 ECEF.z coordinate or altitude,
    /// both if tenths of [mm],
    /// depending on `flags` field.
    #[ubx(map_type = f32, scale = 1.0)]
    ecef_z_or_alt_hp: i8,
    reserved2: u8,
    /// Fixed position 3D accuracy [0.1 mm]
    #[ubx(map_type = f64, scale = 1e-4)]
    fixed_pos_acc: u32,
    /// Survey in minimum duration [s]
    sv_in_min_duration: u32,
    /// Survey in position accuracy limit [0.1 mm]
    #[ubx(map_type = f64, scale = 1e-4)]
    sv_in_accur_limit: u32,
    reserved3: [u8; 8],
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct CfgTmode3RcvrMode: u8 {
        const DISABLED = 0x01;
        const SURVEY_IN = 0x02;
        /// True ARP position is required in `FixedMode`
        const FIXED_MODE = 0x04;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct CfgTmode3Flags: u8 {
        /// Set if position is given in Lat/Lon/Alt,
        /// ECEF coordinates being used otherwise
        const LLA = 0x01;
    }
}

/// CFG_CFG
/// Clear, Save, Load configurations
#[ubx_packet_send]
#[ubx(
    class = 0x06, 
    id = 0x09, 
    fixed_payload_len = 13, 
    flags = "default_for_builder"
)]
struct CfgCfg {
    #[ubx(map_type = CfgCfgMask)]
    clear_mask: u32,
    #[ubx(map_type = CfgCfgMask)]
    save_mask: u32,
    #[ubx(map_type = CfgCfgMask)]
    load_mask: u32,
    #[ubx(map_type = CfgCfgDevMask)]
    dev_mask: u8,
}

#[ubx_extend_bitflags]
#[ubx(into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct CfgCfgMask: u32 {
        const IOPORT = 0x01;
        const MSG_CONF = 0x02;
        const INF_MSG = 0x04;
        const NAV_CONF = 0x08;
        const RXM_CONF = 0x10;
        const SEN_CONF = 0x20;
        const RINV_CONF = 0x40;
        const ANT_CONF = 0x80;
        const LOG_CONF = 0x100;
        const FTS_CONF = 0x200;
    }
}

/// CFG_PM2
/// Power Management 2nd frame
#[ubx_packet_send]
#[ubx(
    class = 0x06, 
    id = 0x3B, 
    fixed_payload_len = 48, 
    flags = "default_for_builder"
)]
struct CfgPm2 {
    /// 0x02 for this version
    version: u8,
    reserved1: u8,
    /// maximal time in [s],
    /// to spend in Acquisition state
    max_startup_state_dur: u8,
    reserved2: u8,
    #[ubx(map_type = CfgPm2Flags)]
    flags: u32,
    /// update period [ms]
    #[ubx(map_type = f32, scale = 1.0)]
    update_period: u32,
    /// search period [ms]
    #[ubx(map_type = f32, scale = 1.0)]
    search_period: u32,
    /// grid offset [ms]
    #[ubx(map_type = f32, scale = 1.0)]
    grid_offset: u32,
    /// time to stay in Tracking state [s]
    #[ubx(map_type = f32, scale = 1.0)]
    on_time: u16,
    /// min search time [s]
    #[ubx(map_type = f32, scale = 1.0)]
    min_acq_time: u16,
    reserved3: [u8; 20],
    /// ext int inactivity [ms]
    #[ubx(map_type = f32, scale = 1.0)]
    ext_int_inactivity: u32,
}

#[ubx_extend_bitflags]
#[ubx(into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    #[derive(Serialize, Deserialize)]
    pub struct CfgPm2Flags: u32 {
        const POWERSAVE = 0x01;
    }
}

#[ubx_extend_bitflags]
#[ubx(into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct CfgCfgDevMask: u8 {
        const BBRAM = 1;
        const FLASH = 2;
        const EEPROM = 4;
        const SPI_FLASH = 8;
    }
}

/// TP5: "Time Pulse" Config frame (32.10.38.4)
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06, 
    id = 0x31, 
    fixed_payload_len = 32,
    flags = "default_for_builder"
)]
struct CfgTp5 {
    #[ubx(map_type = CfgTp5TimePulseMode, may_fail)]
    tp_idx: u8,
    version: u8,
    reserved1: [u8; 2],
    /// Antenna cable delay [ns]
    #[ubx(map_type = f32, scale = 1.0)]
    ant_cable_delay: i16,
    /// RF group delay [ns]
    #[ubx(map_type = f32, scale = 1.0)]
    rf_group_delay: i16,
    /// Frequency in Hz or Period in us,
    /// depending on `flags::IS_FREQ` bit
    #[ubx(map_type = f64, scale = 1.0)]
    freq_period: u32, 
    /// Frequency in Hz or Period in us,
    /// when locked to GPS time.
    /// Only used when `flags::LOCKED_OTHER_SET` is set
    #[ubx(map_type = f64, scale = 1.0)]
    freq_period_lock: u32, 
    /// Pulse length or duty cycle, [us] or [*2^-32],
    /// depending on `flags::LS_LENGTH` bit
    #[ubx(map_type = f64, scale = 1.0)]
    pulse_len_ratio: u32,
    /// Pulse Length in us or duty cycle (*2^-32), 
    /// when locked to GPS time.
    /// Only used when `flags::LOCKED_OTHER_SET` is set
    #[ubx(map_type = f64, scale = 1.0)]
    pulse_len_ratio_lock: u32,
    /// User configurable time pulse delay in [ns]
    #[ubx(map_type = f64, scale = 1.0)]
    user_delay: i32,
    /// Configuration flags, see [CfgTp5Flags]
    #[ubx(map_type = CfgTp5Flags)]
    flags: u32,
}

/// Time pulse selection, used in CfgTp5 frame
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
pub enum CfgTp5TimePulseMode {
    TimePulse = 0,
    TimePulse2 = 1,
}

impl Default for CfgTp5TimePulseMode {
    fn default() -> Self {
        Self::TimePulse
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct CfgTp5Flags: u32 {
        // Enables time pulse
        const ACTIVE = 0x01;
        /// Synchronize time pulse to GNSS as
        /// soon as GNSS time is valid.
        /// Uses local lock otherwise.
        const LOCK_GNSS_FREQ = 0x02;
        /// use `freq_period_lock` and `pulse_len_ratio_lock`
        /// fields as soon as GPS time is valid. Uses 
        /// `freq_period` and `pulse_len_ratio` when GPS time is invalid.
        const LOCKED_OTHER_SET = 0x04;
        /// `freq_period` and `pulse_len_ratio` fields
        /// are interprated as frequency when this bit is set
        const IS_FREQ = 0x08;
        /// Interprate pulse lengths instead of duty cycle
        const IS_LENGTH = 0x10;
        /// Align pulse to top of second
        /// Period time must be integer fraction of `1sec`
        /// `LOCK_GNSS_FREQ` is expected, to unlock this feature
        const ALIGN_TO_TOW = 0x20;
        /// Pulse polarity, 
        /// 0: falling edge @ top of second,
        /// 1: rising edge @ top of second,
        const POLARITY = 0x40;
        /// UTC time grid
        const UTC_TIME_GRID = 0x80;
        /// GPS time grid
        const GPS_TIME_GRID = 0x100;
        /// GLO time grid
        const GLO_TIME_GRID = 0x200;
        /// BDS time grid
        const BDS_TIME_GRID = 0x400;
        /// GAL time grid
        /// not supported in protocol < 18
        const GAL_TIME_GRID = 0x800;
        /// Switches to FreqPeriodLock and PulseLenRatio
        /// as soon as Sync Manager has an accurate time,
        /// never switches back
        const SYNC_MODE_0 = 0x1000;
        /// Switches to FreqPeriodLock and PulseLenRatioLock
        /// as soon as Sync Manager has an accurante time,
        /// and switch back to FreqPeriodLock and PulseLenRatio
        /// when time gets inaccurate
        const SYNC_MODE_1 = 0x2000;
    }
}

#[ubx_extend_bitflags]
#[ubx(into_raw, rest_reserved)]
bitflags! {
    /// Battery backed RAM sections to clear
    pub struct NavBbrMask: u16 {
        const EPHEMERIS = 1;
        const ALMANACH = 2;
        const HEALTH = 4;
        const KLOBUCHARD = 8;
        const POSITION = 16;
        const CLOCK_DRIFT = 32;
        const OSCILATOR_PARAMETER = 64;
        const UTC_CORRECTION_PARAMETERS = 0x80;
        const RTC = 0x100;
        const SFDR_PARAMETERS = 0x800;
        const SFDR_VEHICLE_MONITORING_PARAMETERS = 0x1000;
        const TCT_PARAMETERS = 0x2000;
        const AUTONOMOUS_ORBIT_PARAMETERS = 0x8000;
    }
}

/// Predefined values for `NavBbrMask`
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct NavBbrPredefinedMask(u16);

impl From<NavBbrPredefinedMask> for NavBbrMask {
    fn from(x: NavBbrPredefinedMask) -> Self {
        Self::from_bits_truncate(x.0)
    }
}

impl NavBbrPredefinedMask {
    pub const HOT_START: NavBbrPredefinedMask = NavBbrPredefinedMask(0);
    pub const WARM_START: NavBbrPredefinedMask = NavBbrPredefinedMask(1);
    pub const COLD_START: NavBbrPredefinedMask = NavBbrPredefinedMask(0xFFFF);
}

/// Reset Type
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ResetMode {
    /// Hardware reset (Watchdog) immediately
    HardwareResetImmediately = 0,
    ControlledSoftwareReset = 0x1,
    ControlledSoftwareResetGpsOnly = 0x02,
    /// Hardware reset (Watchdog) after shutdown (>=FW6.0)
    HardwareResetAfterShutdown = 0x04,
    ControlledGpsStop = 0x08,
    ControlledGpsStart = 0x09,
}

/// Port Configuration for I2C
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x00,
    fixed_payload_len = 20,
    flags = "default_for_builder"
)]
struct CfgPrtI2c {
    #[ubx(map_type = I2cPortId, may_fail)]
    portid: u8,
    reserved1: u8,
    /// TX ready PIN configuration
    tx_ready: u16,
    /// I2C Mode Flags
    mode: u32,
    reserved2: u32,
    #[ubx(map_type = InProtoMask)]
    in_proto_mask: u16,
    #[ubx(map_type = OutProtoMask)]
    out_proto_mask: u16,
    flags: u16,
    reserved3: u16,
}

/// Port Identifier Number (= 0 for I2C ports)
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum I2cPortId {
    I2c = 0,
}

impl Default for I2cPortId {
    fn default() -> Self {
        Self::I2c
    }
}

/// Port Configuration for UART
#[ubx_packet_recv_send]
#[ubx(class = 0x06, id = 0x00, fixed_payload_len = 20)]
struct CfgPrtUart {
    #[ubx(map_type = UartPortId, may_fail)]
    portid: u8,
    reserved0: u8,
    tx_ready: u16,
    #[ubx(map_type = UartMode)]
    mode: u32,
    baud_rate: u32,
    #[ubx(map_type = InProtoMask)]
    in_proto_mask: u16,
    #[ubx(map_type = OutProtoMask)]
    out_proto_mask: u16,
    flags: u16,
    reserved5: u16,
}

/// Port Identifier Number (= 1 or 2 for UART ports)
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum UartPortId {
    Uart1 = 1,
    Uart2 = 2,
    Usb = 3,
}

#[derive(Debug, Copy, Clone)]
pub struct UartMode {
    data_bits: DataBits,
    parity: Parity,
    stop_bits: StopBits,
}

impl UartMode {
    pub const fn new(data_bits: DataBits, parity: Parity, stop_bits: StopBits) -> Self {
        Self {
            data_bits,
            parity,
            stop_bits,
        }
    }

    const fn into_raw(self) -> u32 {
        self.data_bits.into_raw() | self.parity.into_raw() | self.stop_bits.into_raw()
    }
}

impl From<u32> for UartMode {
    fn from(mode: u32) -> Self {
        let data_bits = DataBits::from(mode);
        let parity = Parity::from(mode);
        let stop_bits = StopBits::from(mode);

        Self {
            data_bits,
            parity,
            stop_bits,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DataBits {
    Seven,
    Eight,
}

impl DataBits {
    const POSITION: u32 = 6;
    const MASK: u32 = 0b11;

    const fn into_raw(self) -> u32 {
        (match self {
            Self::Seven => 0b10,
            Self::Eight => 0b11,
        }) << Self::POSITION
    }
}

impl From<u32> for DataBits {
    fn from(mode: u32) -> Self {
        match (mode >> Self::POSITION) & Self::MASK {
            0b00 => unimplemented!("five data bits"),
            0b01 => unimplemented!("six data bits"),
            0b10 => Self::Seven,
            0b11 => Self::Eight,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Parity {
    Even,
    Odd,
    None,
}

impl Parity {
    const POSITION: u32 = 9;
    const MASK: u32 = 0b111;

    const fn into_raw(self) -> u32 {
        (match self {
            Self::Even => 0b000,
            Self::Odd => 0b001,
            Self::None => 0b100,
        }) << Self::POSITION
    }
}

impl From<u32> for Parity {
    fn from(mode: u32) -> Self {
        match (mode >> Self::POSITION) & Self::MASK {
            0b000 => Self::Even,
            0b001 => Self::Odd,
            0b100 | 0b101 => Self::None,
            0b010 | 0b011 | 0b110 | 0b111 => unimplemented!("reserved"),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum StopBits {
    One,
    OneHalf,
    Two,
    Half,
}

impl StopBits {
    const POSITION: u32 = 12;
    const MASK: u32 = 0b11;

    const fn into_raw(self) -> u32 {
        (match self {
            Self::One => 0b00,
            Self::OneHalf => 0b01,
            Self::Two => 0b10,
            Self::Half => 0b11,
        }) << Self::POSITION
    }
}

impl From<u32> for StopBits {
    fn from(mode: u32) -> Self {
        match (mode >> Self::POSITION) & Self::MASK {
            0b00 => Self::One,
            0b01 => Self::OneHalf,
            0b10 => Self::Two,
            0b11 => Self::Half,
            _ => unreachable!(),
        }
    }
}

/// Port Configuration for SPI Port
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x00,
    fixed_payload_len = 20,
    flags = "default_for_builder"
)]
struct CfgPrtSpi {
    #[ubx(map_type = SpiPortId, may_fail)]
    portid: u8,
    reserved0: u8,
    /// TX ready PIN configuration
    tx_ready: u16,
    /// SPI Mode Flags
    mode: u32,
    reserved3: u32,
    #[ubx(map_type = InProtoMask)]
    in_proto_mask: u16,
    #[ubx(map_type = OutProtoMask)]
    out_proto_mask: u16,
    flags: u16,
    reserved5: u16,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// A mask describing which input protocols are active
    /// Each bit of this mask is used for a protocol.
    /// Through that, multiple protocols can be defined on a single port
    /// Used in `CfgPrtSpi` and `CfgPrtI2c`
    #[derive(Default)]
    #[derive(Serialize, Deserialize)]
    pub struct InProtoMask: u16 {
        const UBOX = 1;
        const NMEA = 2;
        const RTCM = 4;
        /// The bitfield inRtcm3 is not supported in protocol
        /// versions less than 20
        const RTCM3 = 0x20;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// A mask describing which output protocols are active.
    /// Each bit of this mask is used for a protocol.
    /// Through that, multiple protocols can be defined on a single port
    /// Used in `CfgPrtSpi` and `CfgPrtI2c`
    #[derive(Default)]
    #[derive(Serialize, Deserialize)]
    pub struct OutProtoMask: u16 {
        const UBLOX = 1;
        const NMEA = 2;
        /// The bitfield outRtcm3 is not supported in protocol
        /// versions less than 20
        const RTCM3 = 0x20;
    }
}

/// Port Identifier Number (= 4 for SPI port)
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum SpiPortId {
    Spi = 4,
}

impl Default for SpiPortId {
    fn default() -> Self {
        Self::Spi
    }
}

/// UTC Time Solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x21, fixed_payload_len = 20)]
struct NavTimeUTC {
    /// GPS Millisecond Time of Week
    itow: u32,
    time_accuracy_estimate_ns: u32,

    /// Nanoseconds of second, range -1e9 .. 1e9
    nanos: i32,

    /// Year, range 1999..2099
    year: u16,

    /// Month, range 1..12
    month: u8,

    /// Day of Month, range 1..31
    day: u8,

    /// Hour of Day, range 0..23
    hour: u8,

    /// Minute of Hour, range 0..59
    min: u8,

    /// Seconds of Minute, range 0..59
    sec: u8,

    /// Validity Flags
    #[ubx(map_type = NavTimeUtcFlags)]
    valid: u8,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Validity Flags of `NavTimeUTC`
    pub struct NavTimeUtcFlags: u8 {
        /// Valid Time of Week
        const VALID_TOW = 1;
        /// Valid Week Number
        const VALID_WKN = 2;
        /// Valid UTC (Leap Seconds already known)
        const VALID_UTC = 4;
    }
}

/// Navigation/Measurement Rate Settings
#[ubx_packet_send]
#[ubx(class = 6, id = 8, fixed_payload_len = 6)]
struct CfgRate {
    /// Measurement Rate, GPS measurements are taken every `measure_rate_ms` milliseconds
    measure_rate_ms: u16,

    /// Navigation Rate, in number of measurement cycles.

    /// On u-blox 5 and u-blox 6, this parametercannot be changed, and is always equals 1.
    nav_rate: u16,

    /// Alignment to reference time
    #[ubx(map_type = AlignmentToReferenceTime)]
    time_ref: u16,
}

/// Alignment to reference time
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum AlignmentToReferenceTime {
    Utc = 0,
    Gps = 1,
}

impl AlignmentToReferenceTime {
    const fn into_raw(self) -> u16 {
        self as u16
    }
}

/// Set Message Rate the current port
#[ubx_packet_send]
#[ubx(class = 6, id = 1, fixed_payload_len = 3)]
struct CfgMsgSinglePort {
    msg_class: u8,
    msg_id: u8,

    /// Send rate on current Target
    rate: u8,
}

impl CfgMsgSinglePortBuilder {
    #[inline]
    pub fn set_rate_for<T: UbxPacketMeta>(rate: u8) -> Self {
        Self {
            msg_class: T::CLASS,
            msg_id: T::ID,
            rate,
        }
    }
}

/// Set Message rate configuration
/// Send rate is relative to the event a message is registered on.
/// For example, if the rate of a navigation message is set to 2,
/// the message is sent every second navigation solution
#[ubx_packet_send]
#[ubx(class = 6, id = 1, fixed_payload_len = 8)]
struct CfgMsgAllPorts {
    msg_class: u8,
    msg_id: u8,

    /// Send rate on I/O Port (6 Ports)
    rates: [u8; 6],
}

impl CfgMsgAllPortsBuilder {
    #[inline]
    pub fn set_rate_for<T: UbxPacketMeta>(rates: [u8; 6]) -> Self {
        Self {
            msg_class: T::CLASS,
            msg_id: T::ID,
            rates,
        }
    }
}

/// Navigation Engine Settings
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x24,
    fixed_payload_len = 36,
    flags = "default_for_builder"
)]
struct CfgNav5 {
    /// Only the masked parameters will be applied
    #[ubx(map_type = CfgNav5Params)]
    mask: u16,
    #[ubx(map_type = CfgNav5DynModel, may_fail)]
    dyn_model: u8,
    #[ubx(map_type = CfgNav5FixMode, may_fail)]
    fix_mode: u8,

    /// Fixed altitude (mean sea level) for 2D fixmode (m)
    #[ubx(map_type = f64, scale = 0.01)]
    fixed_alt: i32,

    /// Fixed altitude variance for 2D mode (m^2)
    #[ubx(map_type = f64, scale = 0.0001)]
    fixed_alt_var: u32,

    /// Minimum Elevation for a GNSS satellite to be used in NAV (deg)
    min_elev_degrees: i8,

    /// Reserved
    dr_limit: u8,

    /// Position DOP Mask to use
    #[ubx(map_type = f32, scale = 0.1)]
    pdop: u16,

    /// Time DOP Mask to use
    #[ubx(map_type = f32, scale = 0.1)]
    tdop: u16,

    /// Position Accuracy Mask (m)
    pacc: u16,

    /// Time Accuracy Mask
    /// according to manual unit is "m", but this looks like typo
    tacc: u16,

    /// Static hold threshold
    #[ubx(map_type = f32, scale = 0.01)]
    static_hold_thresh: u8,

    /// DGNSS timeout (seconds)
    dgps_time_out: u8,

    /// Number of satellites required to have
    /// C/N0 above `cno_thresh` for a fix to be attempted
    cno_thresh_num_svs: u8,

    /// C/N0 threshold for deciding whether toattempt a fix (dBHz)
    cno_thresh: u8,
    reserved1: [u8; 2],

    /// Static hold distance threshold (beforequitting static hold)
    static_hold_max_dist: u16,

    /// UTC standard to be used
    #[ubx(map_type = CfgNav5UtcStandard, may_fail)]
    utc_standard: u8,
    reserved2: [u8; 5],
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// `CfgNav5` parameters bitmask
    #[derive(Default)]
    pub struct CfgNav5Params: u16 {
        /// Apply dynamic model settings
        const DYN = 1;
        /// Apply minimum elevation settings
        const MIN_EL = 2;
        /// Apply fix mode settings
       const POS_FIX_MODE = 4;
        /// Reserved
        const DR_LIM = 8;
        /// position mask settings
       const POS_MASK_APPLY = 0x10;
        /// Apply time mask settings
        const TIME_MASK = 0x20;
        /// Apply static hold settings
        const STATIC_HOLD_MASK = 0x40;
        /// Apply DGPS settings
        const DGPS_MASK = 0x80;
        /// Apply CNO threshold settings (cnoThresh, cnoThreshNumSVs)
        const CNO_THRESHOLD = 0x100;
        /// Apply UTC settings (not supported in protocol versions less than 16)
        const UTC = 0x400;
    }
}

/// Dynamic platform model
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum CfgNav5DynModel {
    Portable = 0,
    Stationary = 2,
    Pedestrian = 3,
    Automotive = 4,
    Sea = 5,
    AirborneWithLess1gAcceleration = 6,
    AirborneWithLess2gAcceleration = 7,
    AirborneWith4gAcceleration = 8,
    /// not supported in protocol versions less than 18
    WristWornWatch = 9,
    /// supported in protocol versions 19.2
    Bike = 10,
}

impl Default for CfgNav5DynModel {
    fn default() -> Self {
        Self::AirborneWith4gAcceleration
    }
}

/// Position Fixing Mode
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum CfgNav5FixMode {
    Only2D = 1,
    Only3D = 2,
    Auto2D3D = 3,
}

impl Default for CfgNav5FixMode {
    fn default() -> Self {
        CfgNav5FixMode::Auto2D3D
    }
}

/// UTC standard to be used
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum CfgNav5UtcStandard {
    /// receiver selects based on GNSS configuration (see GNSS timebases)
    Automatic = 0,
    /// UTC as operated by the U.S. NavalObservatory (USNO);
    /// derived from GPStime
    Usno = 3,
    /// UTC as operated by the former Soviet Union; derived from GLONASS time
    UtcSu = 6,
    /// UTC as operated by the National TimeService Center, China;
    /// derived from BeiDou time
    UtcChina = 7,
}

impl Default for CfgNav5UtcStandard {
    fn default() -> Self {
        Self::Automatic
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct ScaleBack<T: FloatCore + FromPrimitive + ToPrimitive>(T);

impl<T: FloatCore + FromPrimitive + ToPrimitive> ScaleBack<T> {
    fn as_i8(self, x: T) -> i8 {
        let x = (x * self.0).round();
        if x < T::from_i8(i8::min_value()).unwrap() {
            i8::min_value()
        } else if x > T::from_i8(i8::max_value()).unwrap() {
            i8::max_value()
        } else {
            x.to_i8().unwrap()
        }
    }
    fn as_i16(self, x: T) -> i16 {
        let x = (x * self.0).round();
        if x < T::from_i16(i16::min_value()).unwrap() {
            i16::min_value()
        } else if x > T::from_i16(i16::max_value()).unwrap() {
            i16::max_value()
        } else {
            x.to_i16().unwrap()
        }
    }

    fn as_i32(self, x: T) -> i32 {
        let x = (x * self.0).round();
        if x < T::from_i32(i32::min_value()).unwrap() {
            i32::min_value()
        } else if x > T::from_i32(i32::max_value()).unwrap() {
            i32::max_value()
        } else {
            x.to_i32().unwrap()
        }
    }

    fn as_u32(self, x: T) -> u32 {
        let x = (x * self.0).round();
        if !x.is_sign_negative() {
            if x <= T::from_u32(u32::max_value()).unwrap() {
                x.to_u32().unwrap()
            } else {
                u32::max_value()
            }
        } else {
            0
        }
    }

    fn as_u16(self, x: T) -> u16 {
        let x = (x * self.0).round();
        if !x.is_sign_negative() {
            if x <= T::from_u16(u16::max_value()).unwrap() {
                x.to_u16().unwrap()
            } else {
                u16::max_value()
            }
        } else {
            0
        }
    }

    fn as_u8(self, x: T) -> u8 {
        let x = (x * self.0).round();
        if !x.is_sign_negative() {
            if x <= T::from_u8(u8::max_value()).unwrap() {
                x.to_u8().unwrap()
            } else {
                u8::max_value()
            }
        } else {
            0
        }
    }
}

/// Navigation Engine Expert Settings
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x23,
    fixed_payload_len = 40,
    flags = "default_for_builder"
)]
struct CfgNavX5 {
    /// Only version 2 supported
    version: u16,

    /// Only the masked parameters will be applied
    #[ubx(map_type = CfgNavX5Params1)]
    mask1: u16,

    #[ubx(map_type = CfgNavX5Params2)]
    mask2: u32,

    /// Reserved
    reserved1: [u8; 2],

    /// Minimum number of satellites for navigation
    min_svs: u8,

    ///Maximum number of satellites for navigation
    max_svs: u8,

    /// Minimum satellite signal level for navigation
    min_cno_dbhz: u8,

    /// Reserved
    reserved2: u8,

    /// initial fix must be 3D
    ini_fix_3d: u8,

    /// Reserved
    reserved3: [u8; 2],

    /// issue acknowledgements for assistance message input
    ack_aiding: u8,

    /// GPS week rollover number
    wkn_rollover: u16,

    /// Permanently attenuated signal compensation
    sig_atten_comp_mode: u8,

    /// Reserved
    reserved4: u8,
    reserved5: [u8; 2],
    reserved6: [u8; 2],

    /// Use Precise Point Positioning (only available with the PPP product variant)
    use_ppp: u8,

    /// AssistNow Autonomous configuration
    aop_cfg: u8,

    /// Reserved
    reserved7: [u8; 2],

    /// Maximum acceptable (modeled) AssistNow Autonomous orbit error
    aop_orb_max_err: u16,

    /// Reserved
    reserved8: [u8; 4],
    reserved9: [u8; 3],

    /// Enable/disable ADR/UDR sensor fusion
    use_adr: u8,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// `CfgNavX51` parameters bitmask
    #[derive(Default)]
    pub struct CfgNavX5Params1: u16 {
        /// apply min/max SVs settings
        const MIN_MAX = 0x4;
        /// apply minimum C/N0 setting
        const MIN_CNO = 0x8;
        /// apply initial 3D fix settings
        const INITIAL_3D_FIX = 0x40;
        /// apply GPS weeknumber rollover settings
        const WKN_ROLL = 0x200;
        /// apply assistance acknowledgement settings
        const AID_ACK = 0x400;
        /// apply usePPP flag
        const USE_PPP = 0x2000;
        /// apply aopCfg (useAOP flag) and aopOrbMaxErr settings (AssistNow Autonomous)
        const AOP_CFG = 0x4000;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// `CfgNavX5Params2` parameters bitmask
    #[derive(Default)]
    pub struct CfgNavX5Params2: u32 {
        ///  apply ADR/UDR sensor fusion on/off setting
        const USE_ADR = 0x40;
        ///  apply signal attenuation compensation feature settings
        const USE_SIG_ATTEN_COMP = 0x80;
    }
}

/// GNSS Assistance ACK UBX-MGA-ACK
#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x60, fixed_payload_len = 8)]
struct MgaAck {
    /// Type of acknowledgment: 0 -> not used, 1 -> accepted
    ack_type: u8,

    /// Version 0
    version: u8,

    /// Provides greater information on what the receiver chose to do with the message contents.
    /// See [MsgAckInfoCode].
    #[ubx(map_type = MsgAckInfoCode)]
    info_code: u8,

    /// UBX message ID of the acknowledged message
    msg_id: u8,

    /// The first 4 bytes of the acknowledged message's payload
    msg_payload_start: [u8; 4],
}

#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MsgAckInfoCode {
    Accepted = 0,
    RejectedNoTime = 1,
    RejectedBadVersion = 2,
    RejectedBadSize = 3,
    RejectedDBStoreFailed = 4,
    RejectedNotReady = 5,
    RejectedUnknownType = 6,
}

/// Hardware status
#[ubx_packet_recv]
#[ubx(class = 0x0a, id = 0x09, fixed_payload_len = 60)]
struct MonHw {
    pin_sel: u32,
    pin_bank: u32,
    pin_dir: u32,
    pin_val: u32,
    noise_per_ms: u16,
    agc_cnt: u16,
    #[ubx(map_type = AntennaStatus)]
    a_status: u8,
    #[ubx(map_type = AntennaPower)]
    a_power: u8,
    flags: u8,
    reserved1: u8,
    used_mask: u32,
    vp: [u8; 17],
    jam_ind: u8,
    reserved2: [u8; 2],
    pin_irq: u32,
    pull_h: u32,
    pull_l: u32,
}

/// GNSS status,
/// gives current selected constellations
#[ubx_packet_recv]
#[ubx(class = 0x0a, id = 0x28, fixed_payload_len = 8)]
struct MonGnss {
    /// Message version: 0x00
    version: u8,
    /// Supported major constellations bit mask
    #[ubx(map_type = MonGnssConstellMask)]
    supported: u8,
    /// Default major GNSS constellations bit mask
    #[ubx(map_type = MonGnssConstellMask)]
    default: u8,
    /// Currently enabled major constellations bit mask
    #[ubx(map_type = MonGnssConstellMask)]
    enabled: u8,
    /// Maximum number of concurent Major GNSS
    /// that can be supported by this receiver
    simultaneous: u8,
    reserved1: [u8; 3],
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    #[derive(Serialize, Deserialize)]
    pub struct MonGnssConstellMask: u8 {
        /// GPS constellation
        const GPS = 0x01;
        /// GLO constellation
        const GLO = 0x02;
        /// BDC constellation
        const BDC = 0x04;
        /// GAL constellation
        const GAL = 0x08;
    }
}

#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AntennaStatus {
    Init = 0,
    DontKnow = 1,
    Ok = 2,
    Short = 3,
    Open = 4,
}

#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AntennaPower {
    Off = 0,
    On = 1,
    DontKnow = 2,
}

pub struct MonVerExtensionIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> core::iter::Iterator for MonVerExtensionIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < self.data.len() {
            let data = &self.data[self.offset..self.offset + 30];
            self.offset += 30;
            Some(mon_ver::convert_to_str_unchecked(data))
        } else {
            None
        }
    }
}

impl fmt::Debug for MonVerExtensionIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonVerExtensionIter").finish()
    }
}

/// Receiver/Software Version
#[ubx_packet_recv]
#[ubx(class = 0x0a, id = 0x04, max_payload_len = 1240)]
struct MonVer {
    #[ubx(map_type = &str, may_fail, from = mon_ver::convert_to_str_unchecked,
          is_valid = mon_ver::is_cstr_valid, get_as_ref)]
    software_version: [u8; 30],
    #[ubx(map_type = &str, may_fail, from = mon_ver::convert_to_str_unchecked,
          is_valid = mon_ver::is_cstr_valid, get_as_ref)]
    hardware_version: [u8; 10],

    /// Extended software information strings
    #[ubx(map_type = MonVerExtensionIter, may_fail,
          from = mon_ver::extension_to_iter,
          is_valid = mon_ver::is_extension_valid)]
    extension: [u8; 0],
}

mod mon_ver {
    use super::MonVerExtensionIter;

    pub(crate) fn convert_to_str_unchecked(bytes: &[u8]) -> &str {
        let null_pos = bytes
            .iter()
            .position(|x| *x == 0)
            .expect("is_cstr_valid bug?");
        core::str::from_utf8(&bytes[0..null_pos])
            .expect("is_cstr_valid should have prevented this code from running")
    }

    pub(crate) fn is_cstr_valid(bytes: &[u8]) -> bool {
        let null_pos = match bytes.iter().position(|x| *x == 0) {
            Some(pos) => pos,
            None => {
                return false;
            }
        };
        core::str::from_utf8(&bytes[0..null_pos]).is_ok()
    }

    pub(crate) fn is_extension_valid(payload: &[u8]) -> bool {
        if payload.len() % 30 == 0 {
            for chunk in payload.chunks(30) {
                if !is_cstr_valid(chunk) {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    pub(crate) fn extension_to_iter(payload: &[u8]) -> MonVerExtensionIter {
        MonVerExtensionIter {
            data: payload,
            offset: 0,
        }
    }
}

#[ubx_packet_recv]
#[ubx(class = 0x02, id = 0x32, fixed_payload_len = 8)]
struct RxmRtcm {
    version: u8,
    flags: u8,
    sub_type: u16,
    ref_station: u16,
    msg_type: u16,
}

/// Synchronization management configuration frame
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x62,
    fixed_payload_len = 20,
    flags = "default_for_builder"
)]
struct CfgSmgr {
    version: u8,
    /// Minimum # of GNSS fixes before we
    /// commit to use it as a source
    min_gnss_fix: u8,
    /// Maximum frequency rate change, in ppb/sec,
    /// when disciplining. Must be < 30 ppb/s.
    #[ubx(map_type = f32, scale = 1.0)] 
    max_freq_change_rate: u16,
    /// Maximum phase correction rate, in ns/s
    /// in coherent time pulse mode.
    /// Must be < 100 ns/s
    max_phase_corr_rate: u16,
    reserved1: u16,
    /// Limit possible deviation in ppb, 
    /// before UBX-TIM-TOS indicates that frequency
    /// is out of tolerance
    #[ubx(map_type = f32, scale = 1.0)] 
    freq_tolerance: u16,
    /// Limit possible deviation, in ns,
    /// before UBX-TIM-TOS indicates that pulse
    /// is out of tolerance
    #[ubx(map_type = f32, scale = 1.0)] 
    time_tolerance: u16,
    /// Message configuration, see [CfgSmgrMsgFlags]
    #[ubx(map_type = CfgSmgrMsgFlags)] 
    msg: u16,
    /// Maximum slew rate, in us/s
    #[ubx(map_type = f32, scale = 1.0)] 
    max_slew_rate: u16,
    /// Configuration flags, see [CfgSmgrFlags]
    #[ubx(map_type = CfgSmgrFlags)]
    flags: u32,
}

/// Synchronization Manager message flags
#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// Sync manager message flags
    #[derive(Default)]
    pub struct CfgSmgrMsgFlags: u16 {
        /// Report internal oscillator estimated offset,
        /// based on oscillator model
        const MEAS_INTERNAL1 = 0x01;
        /// Report internal oscillator offset relative to GNSS
        const MEAS_GNSS = 0x02;
        /// Report internal oscillator offset relative to EXTINT0 source
        const MEAS_EXTINT0 = 0x04;
        /// Report internal oscillator offset relative to EXTINT1 source
        const MEAS_EXTINT1 = 0x08;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// Synchronization Manager config flags
    #[derive(Default)]
    pub struct CfgSmgrFlags: u32 {
        /// Disable internal Osc. disciplining
        const DISABLE_INTERNAL = 0x01;
        /// Disable external Osc. disciplining
        const DISABLE_EXTERNAL = 0x02;
        /// Reference selection preference,
        /// `Best Phase accuracy` when set,
        /// `Best frequency accuracy` when unset
        const BEST_PHASE_ACCURACY_PREFERENCE = 0x04;
        /// Enables GNSS as sync source
        const ENABLE_GNSS = 0x08;
        /// Enables ExtInt0 as sync source
        const ENABLE_EXTINT0 = 0x10;
        /// Enables ExtInt1 as sync source
        const ENABLE_EXTINT1 = 0x20;
        /// Enable host measurements of the internal
        /// oscillator as sync source.
        /// TimSmeasData0 frame should be used
        /// to send measurements data
        const ENABLE_HOST_MEAS_INT = 0x40;
        /// Enable host measurements of the external
        /// oscillator as sync source.
        /// TimSmeasData1 frame should be used
        /// to send measurements data
        const ENABLE_HOST_MEAS_EXT = 0x80;
        /// Uses any fix when asserted,
        /// otherwise, only `over determined` navigation
        /// solutions are used
        const USE_ANY_FIX = 0x100;
        /// MaxSlewRate field is discarded when asserted,
        /// otherwise MaxSlewRate field is used for 
        /// maximum time correction, in corrective fime pulse mode
        const DISABLE_MAX_SLEW_RATE = 0x200;
        /// Issues UBX-TIME-TOS warning when frequency uncertainty
        /// exceeds `freq_tolerance`
        const ISSUE_FREQ_WARNING = 0x400;
        /// Issues UBX-TIME-TOS warning when time uncertainty
        /// exceeds `time_tolerance`
        const ISSUE_TIME_WARNING = 0x800;
        /// Coherence Pulses. Time phase offsets will be corrected
        /// gradually by varying the GNSS oscillator rate within
        /// freq. tolerance limits.
        const TP_COHERENT_PULSES = 0x1000;
        /// Non coherence Pulses. Time phase offsets will be corrected
        /// as quickly as allowed by specified `max_slew_rate`
        const TP_NON_COHERENCE_PULSES = 0x2000;
        /// Post init. coherent pulses.
        /// Starts off in non coherent mode, then automatically switches
        /// to coherent pulse mode, when PLL is locked
        const TP_POST_INIT_COHERENT_PULSES = 0x4000;
        /// Disable automatic storage of oscillator offset
        const DISABLE_OFFSET_STORAGE = 0x8000;
    }
}

/*
/// Jamming / Interference minotor configuration frame
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x39,
    fixed_payload_len = 8,
    flags = "default_for_builder"
)]
struct CfgItfm {

}*/

#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x11,
    fixed_payload_len = 8,
    flags = "default_for_builder"
)]
struct TimDosc {
    /// Message version: 0x00
    version: u8,
    reserved1: [u8; 3],
    /// Raw value to be applied to the DAC
    /// controlling the external OSC.
    /// Write approriate amount of bits as big endian
    value: u32,
}

#[ubx_packet_recv_send]
#[ubx(
    class = 0x0D,
    id = 0x16,
    fixed_payload_len = 32,
    flags = "default_for_builder"
)]
struct TimFchg {
    version: u8,
    reserved: [u8; 3],
    /// GPS time of week of the navigation epoch, in ms,
    /// from which the sync manager obtains the GNSS 
    /// specific data
    itow: u32,
    /// Internal OSC frequency increment in ppb
    #[ubx(map_type = f64, scale = 3.90625E-3)] // 2^-8 
    int_delta_freq: i32,
    /// Internal OSC frequency increment uncertainty, in ppb
    #[ubx(map_type = f64, scale = 3.90625E-3)] // 2^-8
    int_delta_freq_unc: u32,
    /// Current raw DAC command [n/a] 
    internal_raw: u32,
    /// External DAC frequency increment 
    #[ubx(map_type = f64, scale = 3.90625E-3)] // 2^-8
    ext_delta_freq: i32,
    /// External DAC frequency increment uncertainty 
    #[ubx(map_type = f64, scale = 3.90625E-3)] // 2^-8
    ext_delta_freq_inc: u32,
    /// Current raw DAC command [n/a]
    external_raw: u32,
}

/// Oscilator Identification
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum OscillatorId {
    Internal = 0,
    External = 1,
}

impl Default for OscillatorId {
    fn default() -> Self {
        Self::Internal
    }
}

#[ubx_packet_recv_send]
#[ubx(
    class = 0x0D,
    id = 0x17,
    fixed_payload_len = 8,
    flags = "default_for_builder"
)]
struct TimHoc {
    /// Message version: 0x00
    version: u8,
    /// Oscillator ID, 
    #[ubx(map_type = OscillatorId, may_fail)]
    osc_id: u8,
    /// flags
    #[ubx(map_type = TimHocFlags)]
    flags: u8,
    reserved1: u8,
    #[ubx(map_type = f64, scale = 1.0)] // 2^-8 
    /// Required frequency offset or raw output
    value: i32,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct TimHocFlags: u8 {
        const RAW_DIGITAL_OUTPUT = 0x01;
        const VALUE_RELATIVE_TO_CURRENT = 0x02;
    }
}

/*
#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x13,
    max_payload_len = 204, //TODO 12+24*N=8, quel est le N max?
    flags = "default_for_builder",
)]
struct TimSmeas {
    verison: u8,
    /// Number of measurements, in 
    /// case of repeated block
    num_meas: u8,
    reserved1: [u8; 2],
    /// Time of week in [ms]
    itow: u32,
    reserved2: [u8; 2],

    #[ubx(map_type = TimSmeasIter,
        may_fail,
        is_valid = timsmeas::is_valid,
        from = timesmeas::convert_to_iter,
        get_as_ref)]
    meas: [u8, 0],
} */

/// Survey in readable frame
#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x04,
    fixed_payload_len = 28
)]
struct TimSvin {
    duration: u32,
    mean_x: i32,
    mean_y: i32,
    mean_z: i32,
    mean_v: u32,
    obs: u32,
    valid: u8,
    active: u8,
    reserved1: [u8; 2],
}

#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x03,
    fixed_payload_len = 28,
)]
struct TimTm2 {
    ch: u8,
    #[ubx(map_type = TimTm2Flags)]
    flags: u8,
    count: u16,
    wnr: u16,
    wnf: u16,
    to_msr: u32,
    tow_sub_msr: u32,
    tow_msf: u32,
    two_sub_msf: u32,
    acc_est: u32,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    pub struct TimTm2Flags: u8 {
        const RUNNING = 0x01;
        const STOPPED = 0x02;
        const NEW_FALLING_EDGE = 0x04;
        const GNSS_TIME_TIMEBASE = 0x08;
        const UTC_TIME_BASE = 0x10;
        const UTC_AVAILABLE = 0x20;
        const TIME_IS_VALID = 0x40;
        const NEW_RISING_EDGE = 0x80;
    }
}

#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x12,
    fixed_payload_len = 56
)]
struct TimTos {
    version: u8,
    gnss_id: u8,
    reserved1: [u8; 2],
    #[ubx(map_type = TimTosFlags)]
    flags: u32,
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    utc_standard: u8,
    utc_offset: i32,
    utc_uncertainty: u32,
    week: u32,
    tow: u32,
    gnss_offset: i32,
    gnss_uncertainty: u32,
    int_osc_offset: i32,
    int_osc_uncertainty: u32,
    ext_osc_offset: i32,
    ext_osc_uncertainty: u32,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct TimTosFlags: u32 {
        /// Currently in a leap second
        const LEAP_NOW = 0x01;
        /// Leap second in current minute
        const LEAP_CURRENT_MINUTE = 0x02;
        /// Positive leap second
        const POSITIVE_LEAP = 0x04;
        /// Time pulse is within tolerance limit (Ubx-CfgSmgr)
        const TIME_IN_LIMIT = 0x08;
        /// Internal oscillator is within tolerance limit (Ubx-CfgSmgr)
        const INT_OSC_IN_LIMIT = 0x10;
        /// Exteranl oscillator is within tolerance limit (Ubx-CfgSmgr)
        const EXT_OSC_IN_LIMIT = 0x20;
        /// GNSS Time is valid
        const GNSS_TIME_IS_VALID = 0x40;
        /// Disciplining source is GNSS
        const GNSS_DISCIPLINING = 0x80;
        /// Disciplining source is EXTINT0
        const EXTINT0_DISCIPLINING = 0x100;
        /// Disciplining source is EXTINT1
        const EXTINT1_DISCIPLINING = 0x200;
        /// Internal Osc measured by host
        const INT_MEAS_BY_HOST = 0x400;
        /// External Osc measured by host
        const EXT_MEAS_BY_HOST = 0x800;
        /// (T)RAIM system currently active
        const RAIM = 0x1000;
        /// Coherent pulse generation active
        const COHERENT_PULSE = 0x2000;
        /// Time pulse is locked
        const TIME_PULSE_LOCKED = 0x4000;
    }
}

#[ubx_packet_recv]
#[ubx(
    class = 0x0D,
    id = 0x01,
    fixed_payload_len = 16,
)]
struct TimTp {
    two_ms: u32,
    #[ubx(map_type = f64, scale = 2.3283E-10)] // 2^-32 
    two_sub_ms: u32,
    q_err: i32,
    week: u16,
    #[ubx(map_type = TimTpFlags)]
    flags: u8,
    ref_info: u8,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct TimTpFlags: u8 {
        const UTC_TIME_BASE = 0x01;
        const UTC_AVAILABLE = 0x02;
        const RAIM_NOT_ACTIVE = 0x04;
        const RAIM_ACTIVE = 0x08;
        const QUANTIZE_ERROR_INVALID = 0x10;
    }
}

#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x03, fixed_payload_len = 88)]
struct MgaBdsEph {
    /// Message type: 0x01 for this type
    msg_type: u8,
    /// Message version: 0x00 for this version
    version: u8,
    /// BeiDou satellite identifier
    sv_id: u8,
    reserved1: u8,
    /// Autonomous satellite Health flag
    sat_h1: u8,
    /// Issue of Data, clock
    iodc: u8,
    /// Time polynomial coefficient 2 [s/s^2]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-66
    a2: i16,
    /// Time polynomial coefficient 1
    #[ubx(map_type = f64, scale = 1.0)] // 2^-50
    a1: i32,
    /// Time polynomial coefficient 0
    #[ubx(map_type = f64, scale = 1.0)] // 2^-33
    a0: i32,
    /// Clock data reference time
    #[ubx(map_type = f64, scale = 1.0)] // 2^-3
    toc: u32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    tgd1: i16,
    /// TODO 
    urai: u8,
    /// TODO 
    iode: u8,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    toe: u32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    sqrt_a: u32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    e: u32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    omega: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    delta_n: i16,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    idot: i16,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    m0: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    omega0: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    omega_dot: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    i0: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    cuc: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    cus: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    crc: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    crs: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    cic: i32,
    /// TODO 
    #[ubx(map_type = f64, scale = 1.0)] // 2^
    cis: i32,
    reserved2: [u8; 4],
}

#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x03, fixed_payload_len = 16)]
struct MgaBdsIono {
    /// Message type: 0x06 for this type
    msg_type: u8,
    /// Message version: 0x00 for this type
    version: u8,
    reserved1: [u8;2],
    /// Ionospheric parameter alpha0 [s]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-30
    alpha0: i8,
    /// Ionospheric parameter alpha1 [s/pi]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-27
    alpha1: i8,
    /// Ionospheric parameter alpha1 [s/pi^2]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-24
    alpha2: i8,
    /// Ionospheric parameter alpha1 [s/pi^3]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-24
    alpha3: i8,
    /// Ionospheric parameter beta0 [s]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-11
    beta0: i8,
    /// Ionospheric parameter beta1 [s/pi]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-14
    beta1: i8,
    /// Ionospheric parameter beta1 [s/pi^2]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-16
    beta2: i8,
    /// Ionospheric parameter beta1 [s/pi^3]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-16
    beta3: i8,
    reserved2: [u8;4],
}

#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x02, fixed_payload_len = 74)]
struct MgaGalEph {
    /// Message type: 
    /// 0x01 for this type
    msg_type: u8,
    /// MEssage version: 
    /// 0x00 for this version
    version: u8,
    /// Satellite #
    sv_id: u8,
    reserved1: u8,
    /// Ephemerics clock correction 
    /// Issue of Data
    iod_nav: u16,
    /// Mean motion difference from computed value
    /// in semi circles /sec
    #[ubx(map_type = f32, scale = 1.136868E-13)] //2^-43
    delta_n: i16,
    /// Mean anomaly at reference time [semi-circles]
    m0: i32,
    /// Eccentricity
    e: u32,
    /// Square root of semi major axis [sqrt[m]]
    sqrt_a: u32,
    /// Longitude of ascending node of orbital plane [semi-circles]
    /// at weekly epoch
    omega_0: i32,
    /// Inclination angle at reference time [semi-circles]
    i0: i32,
    /// Argument of perigee [semi-circles]
    omega: i32,
    /// Rate of change of right ascension [semi-circles/s]
    omega_dot: i32,
    /// Rate of change of inclination angle [semi-circles/s]
    i_dot: i16,
    /// Amplitude of cosine harmonic correction term
    /// to the argument of latitude [rad]
    cuc: i16,
    /// Amplitude of sine harmonic correction term
    /// to the argument of latitude [rad]
    cus: i16,
    crc: i16,
    cic: i16,
    cis: i16,
    /// Ephemeric reference time
    toe: u16,
    /// SV clock bias correction coefficient
    af0: i32,
    /// SV clock drift correction coefficient
    af1: i32,
    /// SV clock drift rate correction coefficient
    af2: i8,
    sisa_index_e1e5b: u8,
    /// Clock correction data
    toc: u16,
    /// Broadcast group delay
    bgd_e1_e5b: i16,
    reserved2: [u8;2],
    health_e1b: u8,
    data_validity_e1b: u8,
    health_e5b: u8,
    data_validity_e5b: u8,
    reserved3: [u8;4],
}

#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x06, fixed_payload_len = 48)]
struct MgaGloEph {
    msg_type: u8,
    version: u8,
    sv_id: u8,
    reserved1: u8,
    ft: u8,
    b: u8,
    m: u8,
    h: i8,
    x: i32,
    y: i32,
    z: i32,
    dx: i32,
    dy: i32,
    dz: i32,
    ddx: i8,
    ddy: i8,
    ddz: i8,
    tb: u8,
    gamma: u16,
    e: u8,
    delta_tau: u8,
    tau: i32,
    reserved2: [u8;4],
}

#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x00, fixed_payload_len = 68)]
struct MgaGpsEph {
    msg_type: u8,
    version: u8,
    sv_id: u8,
    reserved1: u8,
    fit_interval: u8,
    ura_index: u8,
    sv_health: u8,
    tgd: i8,
    iodc: u16,
    toc: u16,
    reserved2: u8,
    af2: i8,
    af1: i16,
    af0: i32,
    crs: i16,
    delta_n: i16,
    m0: i32,
    cuc: i16,
    cus: i16,
    e: u32,
    sqrt_a: u32,
    toe: u16,
    cic: i16,
    omega0: i32,
    cis: i16,
    crc: i16,
    i0: i32,
    omega: i32,
    omega_dot: i32,
    idot: i16,
    reserved3: [u8;2],
}

#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x00, fixed_payload_len = 16)]
struct MgaGpsIono {
    /// Message type: 0x06 for this type
    msg_type: u8,
    /// Message version: 0x00 for this version
    version: u8,
    reserved1: [u8;2],
    /// Ionospheric parameter alpha0 [s]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-30
    alpha0: i8,
    /// Ionospheric parameter alpha1 [s/semi-circle]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-27
    alpha1: i8,
    /// Ionospheric parameter alpha1 [s/semi-circle^2]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-24
    alpha2: i8,
    /// Ionospheric parameter alpha1 [s/semi-circle^3]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-24
    alpha3: i8,
    /// Ionospheric parameter beta0 [s]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-11
    beta0: i8,
    /// Ionospheric parameter beta0 [s/semi-circle]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-14
    beta1: i8,
    /// Ionospheric parameter beta0 [s/semi-circle^2]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-16
    beta2: i8,
    /// Ionospheric parameter beta0 [s/semi-circle^3]
    #[ubx(map_type = f64, scale = 1.0)] // 2^-16
    beta3: i8,
    reserved2: [u8;4],
}

/*#[ubx_packet_recv]
#[ubx(class = 0x02, id = 0x14, max_payload_len = 2840)]
struct RxmMeasx {
    version: u8,
    reserved1: [u8;3],
    /// GPS measurement ref. time in [s]
    #[ubx(map_type = f64, scale = 1e-3)]
    gps_tow: u32,
    /// GLO measurement ref. time in [s]
    #[ubx(map_type = f64, scale = 1e-3)]
    glo_tow: u32,
    /// BDS measurement ref. time in [s]
    #[ubx(map_type = f64, scale = 1e-3)]
    bds_tow: u32,
    reserved2: [u8; 4],
    /// QZSS measurement ref. time in [s]
    #[ubx(map_type = f64, scale = 1e-3)]
    qzss_tow: u32,
    /// GPS measurement ref. time accuracy [ms]
    #[ubx(map_type = f32, scale = 6.250)] //2^-4
    gps_tow_acc: u16,
    /// GLO measurement ref. time accuracy [ms]
    #[ubx(map_type = f32, scale = 6.250)] //2^-4
    glo_tow_acc: u16,
    /// BDS measurement ref. time accuracy [ms]
    #[ubx(map_type = f32, scale = 6.250)] //2^-4
    bds_tow_acc: u16,
    reserved3: [u8;2],
    /// QZSS measurement ref. time accuracy [ms]
    #[ubx(map_type = f32, scale = 6.250)] //2^-4
    qzss_tow_acc: u16,
    /// Number of sat in repeated block
    num_sv: u8,
    /// flags
    flags: u8, 
    reserved4: [u8;8],
    gnss_id: u8,
    sv_id: u8,
    cno: u8,
    mpath_indic: u8,
    /// Doppler measurement [m/s]
    #[ubx(map_type = f32, scale = 0.04)]
    doppler_ms: i32,
    /// Doppler measurement [Hz]
    #[ubx(map_type = f32, scale = 0.2)]
    doppler_hz: i32,
    whole_chips: u16,
    frac_chips: u16,
    phase: u32,
    intg_cphase: u8,
    pr_rms_err: u8,
    reserved5: [u8;2],
}*/

#[ubx_packet_recv]
#[ubx(class = 0x01, id = 0x26, fixed_payload_len = 24)]
/// NAV Leap Second event information
struct NavTimeLs {
    itow: u32,
    version: u8,
    reserved1: [u8; 3],
    #[ubx(map_type = NavTimeLsLeapSource)]
    leap_source: u8,
    curr_leap: i8,
    #[ubx(map_type = NavTimeLsChangeSource)]
    change_source: u8,
    change: i8,
    time_to_ls_event: i32,
    date_ls_gps_wn: u16,
    date_ls_gps_dn: u16,
    reserved2: [u8; 3],
    #[ubx(map_type = NavTimeLsValidFlags)]
    valid: u8,
}

#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NavTimeLsChangeSource {
    NoSource = 0,
    GPS = 2,
    SBAS = 3,
    BeiDou = 4,
    GAL = 5,
    GLO = 6,
    NavLc = 7,
}

impl Default for NavTimeLsChangeSource {
    fn default() -> Self {
        Self::NoSource
    }
}

#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum NavTimeLsLeapSource {
    Hardcoded = 0,
    GpsGloTimeDifference = 1,
    GPS = 2,
    SBAS = 3,
    BeiDou = 4,
    GAL = 5,
    AidedData = 6,
    Configured = 7,
    NavLc = 8,
    Unknown = 255,
}

impl Default for NavTimeLsLeapSource {
    fn default() -> Self {
        Self::Unknown
    }
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    #[derive(Default)]
    pub struct NavTimeLsValidFlags: u8 {
        const VALID_CURRENT = 0x01;
        const VALID_NEXT = 0x02;
    }
}

define_recv_packets!(
    enum PacketRef {
        _ = UbxUnknownPacketRef,
        NavPosLlh,
        NavStatus,
        NavDop,
        NavPosVelTime,
        NavSolution,
        NavVelNed,
        NavTimeUTC,
        NavSat,
        NavOdo,
        NavEoe,
        NavSvin,
        NavTimeLs,
        //NavOrb,
        //CfgDgnss,
        CfgGnss,
        CfgOdo,
        CfgTp5,
        MgaAck,
        MgaBdsEph,
        MgaBdsIono,
        MgaGalEph,
        MgaGloEph,
        MgaGpsEph,
        MgaGpsIono,
        AlpSrv,
        AckAck,
        AckNak,
        CfgPrtI2c,
        CfgPrtSpi,
        CfgPrtUart,
        CfgNav5,
        CfgAnt,
        CfgSmgr,
        CfgTmode2,
        CfgTmode3,
        InfError,
        InfWarning,
        InfNotice,
        InfTest,
        InfDebug,
        MonVer,
        MonHw,
        MonGnss,
        //RxmMeasx,
        RxmRtcm,
        //TimVcoStopCal,
        //TimVcoCal1,
        //TimVcoCal3,
        TimSvin,
    }
);
